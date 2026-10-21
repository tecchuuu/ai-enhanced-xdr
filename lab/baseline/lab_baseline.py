#!/usr/bin/env python3
"""
Lab baseline — synthetic "normal" SSH + web traffic for the lab test set.

Why this exists: the public dataset (AIT-LDS) covers the WEB lane but has almost
no SSH activity and no SSH attacks at all (failure log Entry 38), so the SSH lane
must be evaluated on our own environment. An anomaly model learns "normal for
HERE" — these users, this volume, these hours — so each environment is trained on
its own clean baseline. This generates that baseline. Attacks come later
(lab/attacker, with an attack_schedule.csv that marks the attack minutes); a lab
loader then turns baseline + attacks into labelled 1-minute windows using the
live detectors' own feature code (ai-stack/pipeline/features.py), exactly as
scripts/ait_windows.py does for AIT.

It writes genuine-format log files; it does NOT open real connections:
  <out>/auth.log     RFC3339 syslog (like the VM's rsyslog): sshd Accepted/Failed
                     with real source IPs, PAM session lines, and CRON noise
  <out>/access.log   Apache combined access log
  <out>/meta.json    sim_start / sim_end of the generated span + the config

Source IPs vary per employee (10.20.0.0/24) — that is the point: it retires the
"everything came from 127.0.0.1, so srcip was unusable as a feature" limitation
(results_log 5.3). Traffic follows a work-hours rhythm: quiet nights, busy
UTC-daytime (02:00-11:00 UTC maps to ~09:00-18:00 Bangkok on the SIAM VM), a
lunch dip, light weekends, a nightly automated backup login, and the occasional
mistyped password so that one lone failure is not by itself abnormal. Everything
is in UTC, like AIT, so the two datasets are directly comparable.

Two modes, one generator (identical content for a given --seed and minute):
  realtime   append each minute as it elapses; run it ~3 days (2 to train, 1 to
             pick the threshold -- the AIT protocol). Start once, walk away.
  simulate   fast-forward: write N days at once. For a quick dataset, or a test.

  python lab/baseline/lab_baseline.py --mode realtime --out /LuckyFive/lab/logs
  python lab/baseline/lab_baseline.py --mode simulate --days 3 --out /tmp/lab

The log lines carry no Wazuh rule level; `max_level` is assigned by the lab
loader (a documented per-line mapping, or genuine levels when the logs are
replayed through Wazuh for the rule baseline).

Honest note for the write-up: scripted normal traffic is smoother than real
users, so the lab's false-alarm rates are optimistic -- the "lab-only
evaluation" caveat (Arp et al.). AIT's normal users are simulated too.
"""
import argparse
import json
import random
import signal
import sys
import time
from datetime import datetime, timedelta, timezone
from pathlib import Path

# --- who generates traffic (edit here) ---------------------------------------
# user, source IP. Distinct IPs are deliberate (retire the 127.0.0.1 limit).
EMPLOYEES = [
    ("alice", "10.20.0.11"),
    ("bob",   "10.20.0.12"),
    ("carol", "10.20.0.13"),
]
# a nightly automated job -> benign off-work-hours SSH, so the model does not
# learn that ALL quiet-hour SSH is anomalous (keeps the night-attack test honest)
BACKUP = ("svc-backup", "10.20.0.5")
# a health check that logs in on a fixed cadence during work hours -> a steady,
# automated part of "normal" that thickens the SSH baseline (real boxes have CI,
# monitoring and deploy logins, not only humans)
MONITOR = ("svc-monitor", "10.20.0.6")

HOST = "lab-target"
USER_AGENT = "Mozilla/5.0 (X11; Linux x86_64; rv:120.0) Gecko/20100101 Firefox/120.0"

# pages a normal user browses; HTML-ish pages also pull a few static assets
PAGES = ["/", "/index.html", "/login", "/dashboard", "/profile",
         "/reports/weekly", "/api/status"]
ASSETS = ["/static/app.css", "/static/app.js", "/static/logo.png", "/favicon.ico"]
RARE_404 = ["/old-page", "/robots.txt", "/.well-known/security.txt", "/wp-login.php"]

# work rhythm, in UTC (02:00-11:00 UTC ~ 09:00-18:00 at UTC+7)
WORK_START_H = 2.0
WORK_END_H = 11.0
LUNCH_H = 6.0            # ~13:00 local dip
BACKUP_HOUR = 19         # ~02:00 local -> genuinely off-hours

# per-employee per-minute probabilities, scaled by the activity multiplier a(t);
# tuned so a workday yields a few SSH logins and a few hundred web requests total
P_LOGIN = 0.010
P_BROWSE = 0.080
P_FATFINGER = 0.08      # a wrong password before a successful login
P_INVALID_USER = 0.03   # a mistyped username
P_404 = 0.05


def activity(dt):
    """0..1 traffic multiplier for a UTC minute: office hours busy, nights/weekends quiet."""
    h = dt.hour + dt.minute / 60.0
    if WORK_START_H <= h < WORK_END_H:
        base = 1.0
        if h < WORK_START_H + 1:          # morning ramp-up
            base *= h - WORK_START_H
        if h > WORK_END_H - 1:            # evening ramp-down
            base *= WORK_END_H - h
        if abs(h - LUNCH_H) < 0.5:        # lunch dip
            base *= 0.4
    else:
        base = 0.03                       # near-silent overnight
    if dt.weekday() >= 5:                 # weekend
        base *= 0.15
    return max(0.0, min(1.0, base))


def minute_rng(seed, dt):
    """Deterministic RNG for one minute -> simulate and realtime agree per --seed."""
    return random.Random(f"{seed}:{int(dt.timestamp()) // 60}")


def _at(dt, rng):
    """A precise event time at a random second/microsecond inside the minute."""
    return dt + timedelta(seconds=rng.randint(0, 59), microseconds=rng.randint(0, 999999))


def _auth_ts(t):
    return t.strftime("%Y-%m-%dT%H:%M:%S.") + f"{t.microsecond:06d}+00:00"


def _access_ts(t):
    return t.strftime("[%d/%b/%Y:%H:%M:%S +0000]")


def gen_minute(dt, seed):
    """All auth.log and access.log lines for one UTC minute."""
    rng = minute_rng(seed, dt)
    a = activity(dt)
    auth, web = [], []

    # CRON noise: no source IP, so the auth lane ignores it; it is just texture
    # that makes auth.log look like a real Linux box (and ~95% of AIT's auth.log).
    if dt.minute == 17 or dt.minute % 10 == 9:
        t = _at(dt, rng)
        pid = 10000 + dt.hour * 60 + dt.minute
        for verb in ("opened", f"closed"):
            kind = "opened for user root by (uid=0)" if verb == "opened" else "closed for user root"
            auth.append(f"{_auth_ts(t)} {HOST} CRON[{pid}]: pam_unix(cron:session): session {kind}")

    # nightly automated backup login (weekdays) -> one benign off-hours session
    if dt.hour == BACKUP_HOUR and dt.minute == 5 and dt.weekday() < 5:
        user, ip = BACKUP
        auth.extend(_ssh_session(dt, rng, user, ip, fail=False, invalid=False))

    # monitoring health check on a fixed cadence during work hours (weekdays) ->
    # a steady automated login that gives the SSH baseline more than human traffic
    if dt.weekday() < 5 and dt.minute in (0, 30) and WORK_START_H <= dt.hour + dt.minute / 60.0 < WORK_END_H:
        user, ip = MONITOR
        auth.extend(_ssh_session(dt, rng, user, ip, fail=False, invalid=False))

    # employees: SSH logins and web browsing during (mostly) work hours
    for user, ip in EMPLOYEES:
        if rng.random() < P_LOGIN * a:
            auth.extend(_ssh_session(dt, rng, user, ip,
                                     fail=rng.random() < P_FATFINGER,
                                     invalid=rng.random() < P_INVALID_USER))
        if rng.random() < P_BROWSE * a:
            web.extend(_web_burst(dt, rng, ip))

    return auth, web


def _ssh_session(dt, rng, user, ip, fail, invalid):
    """One login's lines, in time order (any failures precede the accept), all
    within the minute so they fall in one window."""
    port = rng.randint(40000, 65000)
    pid = rng.randint(1000, 99999)
    tag = f"sshd[{pid}]"
    base = dt + timedelta(seconds=rng.randint(0, 50), microseconds=rng.randint(0, 999999))
    step = [0]

    def ts():
        step[0] += 1
        return _auth_ts(base + timedelta(milliseconds=300 * step[0]))

    lines = []
    if invalid:
        typo = user[:-1] if len(user) > 3 else user + "x"
        lines.append(f"{ts()} {HOST} {tag}: Failed password for invalid user {typo} from {ip} port {port} ssh2")
    if fail:
        lines.append(f"{ts()} {HOST} {tag}: Failed password for {user} from {ip} port {port} ssh2")
    lines.append(f"{ts()} {HOST} {tag}: Accepted password for {user} from {ip} port {port} ssh2")
    lines.append(f"{ts()} {HOST} {tag}: pam_unix(sshd:session): session opened for user {user} by (uid=0)")
    lines.append(f"{ts()} {HOST} {tag}: pam_unix(sshd:session): session closed for user {user}")
    return lines


def _web_burst(dt, rng, ip):
    lines = []
    page = rng.choice(PAGES)
    _req(lines, dt, rng, ip, "GET", page, 200)
    if page in ("/", "/index.html", "/dashboard", "/profile"):   # pages pull assets
        for asset in rng.sample(ASSETS, rng.randint(2, 4)):
            _req(lines, dt, rng, ip, "GET", asset, 200 if rng.random() > 0.3 else 304)
    if page == "/login" and rng.random() < 0.5:                  # submit the form
        _req(lines, dt, rng, ip, "POST", "/login", 302)
    if rng.random() < P_404:                                     # the odd dead link
        _req(lines, dt, rng, ip, "GET", rng.choice(RARE_404), 404)
    return lines


def _req(lines, dt, rng, ip, method, url, status):
    t = _at(dt, rng)
    size = rng.randint(200, 8000) if status < 400 else rng.randint(150, 600)
    lines.append(f'{ip} - - {_access_ts(t)} "{method} {url} HTTP/1.1" {status} {size} '
                 f'"-" "{USER_AGENT}"')


def write_meta(out, start, end, seed):
    meta = {
        "name": f"lab_baseline_{start:%Y%m%d}",
        "lane": "both",
        "host": HOST,
        "sim_start": start.isoformat(),
        "sim_end": end.isoformat(),
        "employees": [u for u, _ in EMPLOYEES] + [BACKUP[0], MONITOR[0]],
        "source_ips": [ip for _, ip in EMPLOYEES] + [BACKUP[1], MONITOR[1]],
        "generated_by": "lab/baseline/lab_baseline.py",
        "synthetic": True,
        "seed": seed,
        "note": "Scripted normal traffic (no real connections). Attacks added "
                "separately with lab/attacker; see failure_log Entry 39.",
    }
    (out / "meta.json").write_text(json.dumps(meta, indent=2), encoding="utf-8")


def run_simulate(out, start, days, seed):
    end = start + timedelta(days=days)
    auth_lines, web_lines = [], []
    m = start
    while m < end:
        a, w = gen_minute(m, seed)
        auth_lines += a
        web_lines += w
        m += timedelta(minutes=1)
    with open(out / "auth.log", "a", encoding="utf-8") as f:
        f.write("\n".join(auth_lines) + ("\n" if auth_lines else ""))
    with open(out / "access.log", "a", encoding="utf-8") as f:
        f.write("\n".join(web_lines) + ("\n" if web_lines else ""))
    write_meta(out, start, end, seed)
    print(f"simulate: {days} day(s) {start:%Y-%m-%d %H:%M} -> {end:%Y-%m-%d %H:%M} UTC | "
          f"{len(auth_lines)} auth lines, {len(web_lines)} access lines -> {out}")


_STOP = False


def _on_signal(*_):
    global _STOP
    _STOP = True


def run_realtime(out, seed):
    signal.signal(signal.SIGINT, _on_signal)
    signal.signal(signal.SIGTERM, _on_signal)          # docker stop
    meta_path = out / "meta.json"
    start = datetime.now(timezone.utc).replace(second=0, microsecond=0)
    if meta_path.exists():                              # resume: keep original start
        try:
            start = datetime.fromisoformat(json.loads(meta_path.read_text())["sim_start"])
        except Exception:
            pass
    auth_f = open(out / "auth.log", "a", encoding="utf-8")
    access_f = open(out / "access.log", "a", encoding="utf-8")
    last = None
    print(f"realtime: appending to {out}/auth.log and access.log every minute "
          f"(start {start:%Y-%m-%d %H:%M} UTC). Ctrl-C / docker stop to end.")
    while not _STOP:
        now = datetime.now(timezone.utc)
        # emit the previous, fully-elapsed minute (so timestamps are in the past)
        m = now.replace(second=0, microsecond=0) - timedelta(minutes=1)
        if m != last:
            a, w = gen_minute(m, seed)
            if a:
                auth_f.write("\n".join(a) + "\n"); auth_f.flush()
            if w:
                access_f.write("\n".join(w) + "\n"); access_f.flush()
            write_meta(out, start, m + timedelta(minutes=1), seed)
            last = m
        # sleep to just past the next minute boundary
        slp = 61 - (datetime.now(timezone.utc).second)
        for _ in range(slp):
            if _STOP:
                break
            time.sleep(1)
    auth_f.close(); access_f.close()
    print("\nstopped.")


def main():
    ap = argparse.ArgumentParser(description=__doc__.split("\n\n")[0])
    ap.add_argument("--out", type=Path, required=True, help="output directory")
    ap.add_argument("--mode", choices=["realtime", "simulate"], required=True)
    ap.add_argument("--days", type=float, default=3, help="simulate: how many days")
    ap.add_argument("--start", help="simulate: UTC start (YYYY-MM-DD or ISO); default: midnight 3 days ago")
    ap.add_argument("--seed", type=int, default=1337)
    a = ap.parse_args()

    a.out.mkdir(parents=True, exist_ok=True)
    if a.mode == "simulate":
        if a.start:
            start = datetime.fromisoformat(a.start)
            start = start.replace(tzinfo=timezone.utc) if start.tzinfo is None else start
        else:
            midnight = datetime.now(timezone.utc).replace(hour=0, minute=0, second=0, microsecond=0)
            start = midnight - timedelta(days=a.days)
        run_simulate(a.out, start, a.days, a.seed)
    else:
        run_realtime(a.out, a.seed)


if __name__ == "__main__":
    main()
