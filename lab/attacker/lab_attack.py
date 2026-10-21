#!/usr/bin/env python3
"""
Lab attacker — synthetic attack log events + ground-truth schedule.

Pairs with lab/baseline/lab_baseline.py. It APPENDS attack lines onto the lab's
existing auth.log / access.log on one attack day, and writes attack_schedule.csv
-- the ground truth that labels the attack minutes (scripts/lab_windows.py reads
it, exactly as scripts/ait_windows.py reads AIT's label files).

Synthetic on purpose (failure log Entry 39/40): the attacker writes attack-shaped
log lines rather than running real tools. The detector only sees window features
(events/min, distinct users, error ratio), which are identical whether hydra or a
script produced the lines -- and generating them lets the attempt-rate be set
exactly, which is what the low-and-slow / detection-floor sweep needs. A real-tool
run (hydra/gobuster/sqlmap) would produce equivalent signatures and can be added
later for a live demo.

Attacker traffic comes from 10.20.9.0/24, distinct from the employees' 10.20.0.0/24,
so attack vs normal is unambiguous even inside one window. Attacks land on a
WEEKDAY in the baseline's span (default: baseline start + 4 days = the Friday),
on top of that day's normal traffic.

    python lab/attacker/lab_attack.py --logs /LuckyFive/lab/logs          # read meta, attack the default day
    python lab/attacker/lab_attack.py --logs /LuckyFive/lab/logs --date 2026-10-23

Re-running appends again; pass --reset to drop a previous run's attack lines and
schedule first (keeps the normal baseline).
"""
import argparse
import csv
import json
import random
import re
from datetime import datetime, timedelta, timezone
from pathlib import Path

HOST = "lab-target"
UA = "Mozilla/5.0 (X11; Linux x86_64; rv:120.0) Gecko/20100101 Firefox/120.0"
A1 = "10.20.9.11"                                   # the single attacker host
SWARM = [f"10.20.9.{i}" for i in range(21, 31)]     # distributed brute force
SPRAY_USERS = ["root", "admin", "oracle", "postgres", "git", "jenkins", "deploy",
               "test", "ubuntu", "ec2-user", "ftp", "mysql", "www-data", "backup",
               "guest", "operator", "support", "dev", "sysadmin", "nagios"]
SCAN_PATHS = ["/admin", "/wp-admin", "/phpmyadmin", "/.git/config", "/.env",
              "/backup.zip", "/config.php", "/server-status", "/api/v1/users",
              "/old", "/test", "/db", "/shell.php", "/uploads", "/cgi-bin/test"]
SQLI = ["/item?id=1' OR '1'='1", "/item?id=1 UNION SELECT username,password FROM users",
        "/search?q=x';DROP TABLE users;--", "/login?user=admin'--",
        "/item?id=1 AND SLEEP(5)", "/p?id=1 UNION SELECT 1,2,information_schema.tables"]
XSS = ["/search?q=<script>alert(1)</script>", "/comment?text=<script>document.cookie</script>",
       "/p?name=<img src=x onerror=alert(1)>", "/s?q=%3Cscript%3Ealert(1)%3C/script%3E"]
TRAVERSAL = ["/download?file=../../../../etc/passwd", "/view?p=..%2f..%2f..%2fetc%2fpasswd",
             "/static/../../../../etc/passwd", "/f?name=..\\..\\..\\boot.ini", "/img?x=%2e%2e%2f%2e%2e%2fetc%2fpasswd"]

ATTACK_TAG = "# lab-attack"            # marker on every attack line, for --reset


def auth_ts(t):
    return t.strftime("%Y-%m-%dT%H:%M:%S.") + f"{t.microsecond:06d}+00:00"


def access_ts(t):
    return t.strftime("[%d/%b/%Y:%H:%M:%S +0000]")


def _ssh_fail(t, rng, user, ip, invalid=False):
    who = f"invalid user {user}" if invalid else user
    return (f"{auth_ts(t)} {HOST} sshd[{rng.randint(1000,99999)}]: "
            f"Failed password for {who} from {ip} port {rng.randint(40000,65000)} ssh2 {ATTACK_TAG}")


def _ssh_accept(t, rng, user, ip):
    return (f"{auth_ts(t)} {HOST} sshd[{rng.randint(1000,99999)}]: "
            f"Accepted password for {user} from {ip} port {rng.randint(40000,65000)} ssh2 {ATTACK_TAG}")


def _req(t, rng, ip, method, url, status):
    size = rng.randint(120, 700)
    # a real client percent-encodes spaces; an access-log request field with raw
    # spaces is malformed and Wazuh's web decoder (rightly) rejects it. Encode
    # spaces so the payloads log — and decode — the way sqlmap/gobuster's would.
    url = url.replace(" ", "%20")
    return f'{ip} - - {access_ts(t)} "{method} {url} HTTP/1.1" {status} {size} "-" "{UA}" {ATTACK_TAG}'


# --- attacks: each returns (auth_lines, web_lines) and we log its schedule row --
def ssh_brute(day, start_min, rng, dur_min=3, rate=40, user="root", ip=A1, success=True):
    auth = []
    base = day + timedelta(minutes=start_min)
    for i in range(dur_min * rate):
        t = base + timedelta(seconds=i * 60.0 / rate, microseconds=rng.randint(0, 999))
        auth.append(_ssh_fail(t, rng, user, ip))
    if success:
        auth.append(_ssh_accept(base + timedelta(minutes=dur_min, seconds=1), rng, user, ip))
    end = base + timedelta(minutes=dur_min, seconds=2)
    return auth, [], (base, end, ip, "auth", "ssh_brute_force", f"{rate}/min x{dur_min}min user={user}")


def ssh_spray(day, start_min, rng, dur_min=3, ip=A1):
    auth = []
    base = day + timedelta(minutes=start_min)
    step = dur_min * 60.0 / len(SPRAY_USERS)
    for i, user in enumerate(SPRAY_USERS):
        t = base + timedelta(seconds=i * step, microseconds=rng.randint(0, 999))
        auth.append(_ssh_fail(t, rng, user, ip, invalid=user not in ("root", "www-data", "backup")))
    return auth, [], (base, base + timedelta(minutes=dur_min), ip,
                      "auth", "ssh_password_spray", f"{len(SPRAY_USERS)} users one try each")


def ssh_distributed(day, start_min, rng, per_ip=4):
    auth = []
    base = day + timedelta(minutes=start_min)
    for ip in SWARM:
        for _ in range(per_ip):
            t = base + timedelta(seconds=rng.randint(0, 59), microseconds=rng.randint(0, 999))
            auth.append(_ssh_fail(t, rng, rng.choice(SPRAY_USERS), ip))
    return auth, [], (base, base + timedelta(minutes=1), f"{len(SWARM)} IPs",
                      "auth", "ssh_distributed", f"{len(SWARM)} IPs x{per_ip} each in 1 min")


def ssh_slow(day, start_min, rng, interval_s, count, user="root", ip=A1):
    auth = []
    base = day + timedelta(minutes=start_min)
    for i in range(count):
        t = base + timedelta(seconds=i * interval_s, microseconds=rng.randint(0, 999))
        auth.append(_ssh_fail(t, rng, user, ip))
    end = base + timedelta(seconds=(count - 1) * interval_s + 1)
    return auth, [], (base, end, ip, "auth", f"ssh_slow_{interval_s}s",
                      f"1 attempt / {interval_s}s x{count}")


def web_scan(day, start_min, rng, dur_min=2, rate=150, ip=A1):
    web = []
    base = day + timedelta(minutes=start_min)
    for i in range(dur_min * rate):
        t = base + timedelta(seconds=i * 60.0 / rate, microseconds=rng.randint(0, 999))
        path = rng.choice(SCAN_PATHS) + (f"{rng.randint(0,9999)}" if rng.random() < 0.6 else "")
        web.append(_req(t, rng, ip, "GET", path, 404 if rng.random() < 0.95 else 200))
    return [], web, (base, base + timedelta(minutes=dur_min), ip,
                     "web", "web_content_discovery", f"{rate}/min x{dur_min}min, ~95% 404")


def web_login_brute(day, start_min, rng, dur_min=2, rate=30, ip=A1):
    web = []
    base = day + timedelta(minutes=start_min)
    for i in range(dur_min * rate):
        t = base + timedelta(seconds=i * 60.0 / rate, microseconds=rng.randint(0, 999))
        web.append(_req(t, rng, ip, "POST", "/login", 401 if rng.random() < 0.95 else 302))
    return [], web, (base, base + timedelta(minutes=dur_min), ip,
                     "web", "web_login_bruteforce", f"{rate} POST/min x{dur_min}min to /login")


def web_payloads(day, start_min, rng, payloads, kind, ip=A1):
    web = []
    base = day + timedelta(minutes=start_min)
    for i, url in enumerate(payloads):
        t = base + timedelta(seconds=i * 8, microseconds=rng.randint(0, 999))
        web.append(_req(t, rng, ip, "GET", url, rng.choice([200, 404, 500])))
    return [], web, (base, base + timedelta(minutes=2), ip, "web", kind, f"{len(payloads)} crafted requests")


# offset-from-day-start (UTC minutes) -> attack. Spread across the day; a couple
# run off work-hours (the night brute force) to test the `hour` feature's effect.
def build(day, seed):
    rng = random.Random(f"{seed}:attack")
    plan = [
        web_scan(day, 3 * 60, rng),                       # 03:00 loud scan
        web_login_brute(day, 3 * 60 + 30, rng),           # 03:30
        web_payloads(day, 4 * 60, rng, SQLI, "web_sqli"),         # 04:00
        web_payloads(day, 4 * 60 + 5, rng, XSS, "web_xss"),       # 04:05
        web_payloads(day, 4 * 60 + 10, rng, TRAVERSAL, "web_path_traversal"),  # 04:10
        ssh_brute(day, 5 * 60, rng),                      # 05:00 fast brute force
        ssh_spray(day, 5 * 60 + 30, rng),                 # 05:30 password spray
        ssh_distributed(day, 6 * 60, rng),                # 06:00 many IPs
        ssh_slow(day, 7 * 60, rng, interval_s=60, count=10),      # 07:00  1/min
        ssh_slow(day, 7 * 60 + 30, rng, interval_s=180, count=6), # 07:30  1/3min
        ssh_slow(day, 8 * 60, rng, interval_s=360, count=5),      # 08:00  1/6min
        ssh_brute(day, 20 * 60, rng, rate=30, dur_min=2, success=False),  # 20:00 night brute (off-hours)
    ]
    auth, web, rows = [], [], []
    for a, w, row in plan:
        auth += a
        web += w
        rows.append(row)
    return auth, web, rows


def reset(logs):
    for name in ("auth.log", "access.log"):
        p = logs / name
        if p.exists():
            kept = [ln for ln in p.read_text(encoding="utf-8").splitlines() if ATTACK_TAG not in ln]
            p.write_text("\n".join(kept) + ("\n" if kept else ""), encoding="utf-8")
    (logs / "attack_schedule.csv").unlink(missing_ok=True)
    print("reset: previous attack lines and schedule removed (baseline kept)")


def main():
    ap = argparse.ArgumentParser(description=__doc__.split("\n\n")[0])
    ap.add_argument("--logs", type=Path, required=True, help="the baseline's log dir (auth.log/access.log/meta.json)")
    ap.add_argument("--date", help="attack day, YYYY-MM-DD UTC (default: baseline start + 4 days)")
    ap.add_argument("--seed", type=int, default=1337)
    ap.add_argument("--reset", action="store_true", help="drop a previous attack run first")
    a = ap.parse_args()

    meta = json.loads((a.logs / "meta.json").read_text(encoding="utf-8"))
    start = datetime.fromisoformat(meta["sim_start"])
    end = datetime.fromisoformat(meta["sim_end"])
    if a.date:
        day = datetime.fromisoformat(a.date).replace(tzinfo=timezone.utc)
    else:
        day = (start + timedelta(days=4)).replace(hour=0, minute=0, second=0, microsecond=0)
    if not (start <= day < end):
        raise SystemExit(f"attack day {day:%Y-%m-%d} is outside the baseline span "
                         f"{start:%Y-%m-%d}..{end:%Y-%m-%d}")
    if day.weekday() >= 5:
        print(f"warning: {day:%Y-%m-%d} is a weekend (little normal traffic to hide in)")

    if a.reset:
        reset(a.logs)

    auth, web, rows = build(day, a.seed)
    with open(a.logs / "auth.log", "a", encoding="utf-8") as f:
        f.write("\n".join(auth) + "\n")
    with open(a.logs / "access.log", "a", encoding="utf-8") as f:
        f.write("\n".join(web) + "\n")

    sched = a.logs / "attack_schedule.csv"
    new = not sched.exists()
    with open(sched, "a", newline="", encoding="utf-8") as f:
        w = csv.writer(f)
        if new:
            w.writerow(["start", "end", "attacker_ip", "lane", "type", "params"])
        for s, e, ip, lane, typ, params in rows:
            w.writerow([s.isoformat(), e.isoformat(), ip, lane, typ, params])

    print(f"attack day {day:%Y-%m-%d} UTC: {len(auth)} auth lines, {len(web)} access lines, "
          f"{len(rows)} attacks -> {a.logs}")
    for s, e, ip, lane, typ, params in rows:
        print(f"  {s:%H:%M}-{e:%H:%M} [{lane}] {typ:22s} {ip:14s} {params}")


if __name__ == "__main__":
    main()
