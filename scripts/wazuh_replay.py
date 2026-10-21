#!/usr/bin/env python3
"""Replay a log file through Wazuh's analysis engine -> per-line rule id + level.

The lab/AIT evaluation assigns auth levels by hand (Accepted=3, Failed=5). This
feeds the same log lines through the REAL Wazuh ruleset (wazuh-logtest in the
manager container) so each line gets its genuine rule id and level, including the
correlation rules (sshd brute force 5712/5720, web attack 31xxx) that only fire
after several events -- which is what the "AI vs Wazuh rules" baseline needs
(failure log Entry 40). Runs on the SIAM VM, where the manager container is.

One wazuh-logtest session processes the whole file in order, so the frequency /
timeframe rules see the events in sequence and escalate exactly as they would
live. Output is a CSV (timestamp, rule_id, level, groups) aligned to the input
lines by the "full event:" echo, for scripts/lab_windows.py --rules to fold into
the windows.

    python scripts/wazuh_replay.py --in /LuckyFive/lab/logs/auth.log   --lane auth --out /LuckyFive/eval/auth.ruled.csv
    python scripts/wazuh_replay.py --in /LuckyFive/lab/logs/access.log --lane web  --out /LuckyFive/eval/web.ruled.csv

--container defaults to the compose name; override if yours differs.
"""
import argparse
import csv
import re
import subprocess
import sys
from datetime import datetime, timezone
from pathlib import Path

CONTAINER = "luckyfive_wazuh-wazuh.manager-1"
LOGTEST = "/var/ossec/bin/wazuh-logtest"

FULL = re.compile(r"full event: '(.*)'")
RID = re.compile(r"^\s*id: '(\d+)'", re.M)
LVL = re.compile(r"^\s*level: '(\d+)'", re.M)
GRP = re.compile(r"^\s*groups: '(.*)'", re.M)
WEB_TS = re.compile(r"\[(\d\d/[A-Za-z]{3}/\d{4}:\d\d:\d\d:\d\d [^\]]+)\]")


def parse_ts(line, lane):
    """The event's own timestamp -> UTC, parsed from the raw line (not Wazuh's echo)."""
    if lane == "auth":
        return datetime.fromisoformat(line.split(" ", 1)[0]).astimezone(timezone.utc)
    m = WEB_TS.search(line)
    return datetime.strptime(m.group(1), "%d/%b/%Y:%H:%M:%S %z").astimezone(timezone.utc) if m else None


def run_logtest(lines, container):
    """Feed all lines through one wazuh-logtest session; return its output.
    stderr is merged into stdout because wazuh-logtest writes its phase output
    to stderr."""
    proc = subprocess.run(
        ["docker", "exec", "-i", container, LOGTEST],
        input="\n".join(lines) + "\n",
        stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True,
    )
    if not proc.stdout:
        sys.exit(f"wazuh-logtest produced no output (exit {proc.returncode})")
    return proc.stdout


def main():
    ap = argparse.ArgumentParser(description=__doc__.split("\n\n")[0])
    ap.add_argument("--in", dest="inp", type=Path, required=True)
    ap.add_argument("--lane", choices=["auth", "web"], required=True)
    ap.add_argument("--out", type=Path, required=True)
    ap.add_argument("--container", default=CONTAINER)
    a = ap.parse_args()

    # drop blanks and our own attack marker (lab/attacker ATTACK_TAG), so Wazuh
    # sees a clean log line
    lines = [ln.split(" # lab-attack")[0].rstrip()
             for ln in a.inp.read_text(encoding="utf-8", errors="replace").splitlines() if ln.strip()]
    out = run_logtest(lines, a.container)

    # one block per input line; each starts at "**Phase 1" and echoes "full event:"
    blocks = out.split("**Phase 1: Completed pre-decoding.")[1:]
    if not blocks:
        sys.exit("no '**Phase 1' blocks in the logtest output — the format is "
                 f"unexpected. First 800 chars:\n{out[:800]}")
    if len(blocks) != len(lines):
        print(f"warning: {len(lines)} lines but {len(blocks)} logtest blocks — "
              f"pairing by the echoed full event instead of position")

    by_event = {}
    for b in blocks:
        fe = FULL.search(b)
        if not fe:
            continue
        rid = RID.search(b)
        lvl = LVL.search(b)
        grp = GRP.search(b)
        by_event[fe.group(1)] = (int(rid.group(1)) if rid else 0,
                                 int(lvl.group(1)) if lvl else 0,
                                 grp.group(1) if grp else "")

    a.out.parent.mkdir(parents=True, exist_ok=True)
    matched = flagged = 0
    with open(a.out, "w", newline="", encoding="utf-8") as f:
        w = csv.writer(f)
        w.writerow(["timestamp", "rule_id", "level", "groups"])
        for ln in lines:
            rid, lvl, grp = by_event.get(ln, (0, 0, ""))
            matched += ln in by_event
            flagged += lvl > 0
            ts = parse_ts(ln, a.lane)
            w.writerow([ts.isoformat() if ts else "", rid, lvl, grp])

    print(f"{a.lane}: {len(lines)} lines, {matched} found in logtest output, "
          f"{flagged} raised a rule -> {a.out}")
    if matched < len(lines):
        print("  (lines not found decoded to nothing / did not echo; counted as level 0)")


if __name__ == "__main__":
    main()
