#!/usr/bin/env python3
"""Lab logs -> labelled 1-minute windows (auth + web), for scripts/evaluate.py.

Reads the lab's auth.log + access.log (lab/baseline + lab/attacker), its
meta.json (span) and attack_schedule.csv (ground truth), and writes one window
CSV per lane with the same feature columns the live detectors use
(ai-stack/pipeline/features.py) plus a `label` (1 if the minute overlaps a
scheduled attack for that lane) and `steps` (the attack type(s) in it). Same
shape as scripts/ait_windows.py, so scripts/evaluate.py runs on it unchanged.

    python scripts/lab_windows.py --logs /LuckyFive/lab/logs --out /LuckyFive/eval
    # -> /LuckyFive/eval/lab_auth.csv (+ .meta.json), lab_web.csv (+ .meta.json)
    python scripts/evaluate.py /LuckyFive/eval/lab_*.csv --out /LuckyFive/eval/lab \\
        --train-days 3 --val-days 1

Auth rule level is assigned per line (Accepted=3, Failed/invalid=5) -- enough for
the `max_level` feature offline. Genuine Wazuh levels and the rule baseline come
from replaying these same logs through Wazuh (failure log Entry 40).
"""
import argparse
import csv
import json
from collections import defaultdict
from datetime import datetime, timedelta, timezone
from pathlib import Path
import re
import sys

import pandas as pd

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "ai-stack" / "pipeline"))
from features import (AUTH_FEATURES, WEB_FEATURES, auth_row, fold_auth, fold_web,  # noqa: E402
                      new_auth_window, new_web_window, web_row, window_key, window_start)

SSH_RE = re.compile(r"sshd\[\d+\]: (Accepted|Failed) password for (?:invalid user )?(\S+) from (\d+\.\d+\.\d+\.\d+)")
ACCESS_RE = re.compile(r'^(?P<ip>\S+) \S+ \S+ \[(?P<ts>[^\]]+)\] "(?P<m>[A-Z]+) (?P<u>\S+) HTTP/[\d.]+" (?P<s>\d{3})')
AUTH_LEVEL = {"Accepted": 3, "Failed": 5}


def load_schedule(path, lane):
    """List of (start, end, type) for one lane."""
    if not path.exists():
        return []
    out = []
    for r in csv.DictReader(open(path, encoding="utf-8")):
        if r["lane"] == lane:
            out.append((datetime.fromisoformat(r["start"]), datetime.fromisoformat(r["end"]), r["type"]))
    return out


def load_rules(path):
    """<lane>.ruled.csv (scripts/wazuh_replay.py) -> {window_key: max Wazuh level}."""
    levels = {}
    for r in csv.DictReader(open(path, encoding="utf-8")):
        if not r["timestamp"]:
            continue
        key = window_key(datetime.fromisoformat(r["timestamp"]))
        levels[key] = max(levels.get(key, 0), int(r["level"]))
    return levels


def labels_for(key, schedule):
    """Attack types whose window overlaps this minute (empty = normal)."""
    m0 = window_start(key)
    m1 = m0 + timedelta(minutes=1)
    return sorted({typ for s, e, typ in schedule if s < m1 and e >= m0})


def build_auth(logs, start, end, schedule, rules):
    windows = defaultdict(new_auth_window)
    for raw in open(logs / "auth.log", encoding="utf-8", errors="replace"):
        m = SSH_RE.search(raw)
        if not m:
            continue                       # PAM/CRON lines have no source IP -> not auth events
        ts = datetime.fromisoformat(raw.split(" ", 1)[0])
        if not (start <= ts < end):
            continue
        fold_auth(windows[window_key(ts)], m.group(3), AUTH_LEVEL[m.group(1)], m.group(2))
    # with a Wazuh replay, use the genuine level (incl. brute-force correlation)
    # for the max_level feature instead of the per-line approximation
    return _frame(windows, auth_row, AUTH_FEATURES, schedule, rules, real_max_level=bool(rules))


def build_web(logs, start, end, schedule, rules):
    windows = defaultdict(new_web_window)
    for raw in open(logs / "access.log", encoding="utf-8", errors="replace"):
        m = ACCESS_RE.match(raw)
        if not m:
            continue
        ts = datetime.strptime(m["ts"], "%d/%b/%Y:%H:%M:%S %z").astimezone(timezone.utc)
        if not (start <= ts < end):
            continue
        fold_web(windows[window_key(ts)], m["u"], m["m"], m["s"], m["ip"])
    return _frame(windows, web_row, WEB_FEATURES, schedule, rules, real_max_level=False)


def _frame(windows, row_fn, feats, schedule, rules, real_max_level):
    rows = []
    for key, w in windows.items():
        row = row_fn(key, w)
        steps = labels_for(key, schedule)
        if real_max_level and "max_level" in row:
            row["max_level"] = rules.get(key, 0)      # genuine Wazuh level
        rows.append({
            "timestamp": row["timestamp"].isoformat(),
            **{f: row[f] for f in feats},
            "label": int(bool(steps)),
            "steps": ";".join(steps),
            "rule_level": rules.get(key, 0) if rules else "",   # max Wazuh level in the window
            "top_ips": ";".join(f"{ip}:{n}" for ip, n in row["top_ips"]),
        })
    df = pd.DataFrame(rows).sort_values("timestamp").reset_index(drop=True)
    if not rules:
        df = df.drop(columns=["rule_level"])
    return df


def main():
    ap = argparse.ArgumentParser(description=__doc__.split("\n\n")[0])
    ap.add_argument("--logs", type=Path, required=True)
    ap.add_argument("--out", type=Path, required=True)
    ap.add_argument("--rules", type=Path, help="dir with <lane>.ruled.csv from wazuh_replay.py "
                    "(adds a rule_level column + genuine auth levels; enables the rules baseline)")
    a = ap.parse_args()

    meta = json.loads((a.logs / "meta.json").read_text(encoding="utf-8"))
    start, end = datetime.fromisoformat(meta["sim_start"]), datetime.fromisoformat(meta["sim_end"])
    sched_path = a.logs / "attack_schedule.csv"
    a.out.mkdir(parents=True, exist_ok=True)

    for lane, builder in (("auth", build_auth), ("web", build_web)):
        schedule = load_schedule(sched_path, lane)
        ruled = a.rules / f"{lane}.ruled.csv" if a.rules else None
        rules = load_rules(ruled) if ruled and ruled.exists() else {}
        df = builder(a.logs, start, end, schedule, rules)
        csv_path = a.out / f"lab_{lane}.csv"
        df.to_csv(csv_path, index=False)
        m = {"scenario": f"lab_{lane}", "lane": lane, "host": meta.get("host"),
             "sim_start": start.isoformat(), "sim_end": end.isoformat(),
             "windows": len(df), "attack_windows": int(df["label"].sum()),
             "attacks_scheduled": len(schedule)}
        Path(str(csv_path) + ".meta.json").write_text(json.dumps(m, indent=2), encoding="utf-8")
        print(json.dumps(m))


if __name__ == "__main__":
    main()
