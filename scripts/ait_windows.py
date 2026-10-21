#!/usr/bin/env python3
"""AIT-LDS scenario -> labelled 1-minute web windows, for scripts/evaluate.py.

Reads one scenario of the AIT Log Data Set (v2.0 / v2.1 — Landauer et al.,
IEEE TDSC 2023; Zenodo 10.5281/zenodo.5789064), unzipped from
<scenario>_no-pcaps.zip:

    gather/intranet_server/logs/apache2/intranet.*-access.log*   the WordPress server AIT attacks
    labels/<same relative path>                                  JSON lines: {"line": N, "labels": [...]}
    dataset.yaml                                                 simulation start / end (UTC)

Each request is folded into its window with the live web detector's own code
(ai-stack/pipeline/features.py), so the features are exactly production's. A
window is an attack window if it holds at least one labelled line; the union
of its lines' AIT labels (dirb, wpscan, webshell_cmd, ...) is kept for
per-step recall. Only minutes with at least one request become windows — as in
the live detector, which never sees an empty minute.

Windows are bucketed by the timestamp inside each line, not file order, and
lines outside the simulation window are dropped (AIT: files can hold testbed
setup events). Request lines the live detector could not parse either (no
"METHOD URL HTTP/x") are skipped and counted in the sidecar, labelled or not.

Web lane only: on this host AIT's auth.log has a handful of sshd lines in four
days, and the attack reaches it only through su/sudo — nothing the SSH lane
(remote logins) sees. The SSH lane is evaluated on lab data (failure log
Entry 38).

    python scripts/ait_windows.py /LuckyFive/datasets/ait-lds/russellmitchell \\
        -o results/eval/russellmitchell_web.csv

Writes the CSV and <csv>.meta.json (simulation window, line counts) next to it.
"""
import argparse
import glob
import json
import os
import re
import sys
from collections import Counter, defaultdict
from datetime import datetime, timezone
from pathlib import Path

import pandas as pd

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "ai-stack" / "pipeline"))
from features import WEB_FEATURES, fold_web, new_web_window, web_row, window_key  # noqa: E402

# Apache combined log: IP - user [21/Jan/2022:05:55:22 +0000] "GET /x HTTP/1.1" 200 6202 ...
LINE_RE = re.compile(r'^(?P<ip>\S+) \S+ \S+ \[(?P<ts>[^\]]+)\] "(?P<req>[^"]*)" (?P<status>\d{3}) ')
# the live detector's own request shape (web_detection_consumer.ACCESS_RE)
REQ_RE = re.compile(r'^(?P<method>[A-Z]+)\s+(?P<url>\S+)\s+HTTP/[\d.]+$')


def sim_window(scenario):
    """(start, end) of the simulation from dataset.yaml, as UTC datetimes."""
    text = (scenario / "dataset.yaml").read_text(encoding="utf-8")
    def field(name):
        m = re.search(rf"^{name}:\s*'?([0-9T:\- ]+)'?\s*$", text, re.M)
        if not m:
            sys.exit(f"{scenario}/dataset.yaml: no '{name}:' field")
        return datetime.fromisoformat(m.group(1).strip()).replace(tzinfo=timezone.utc)
    return field("start"), field("end")


def load_labels(path):
    """line number (1-based) -> set of AIT labels, or {} if the file has none."""
    if not path.exists():
        return {}
    out = {}
    for raw in path.read_text(encoding="utf-8").splitlines():
        if raw.strip():
            d = json.loads(raw)
            out[int(d["line"])] = set(d["labels"])
    return out


def build(scenario, host, pattern):
    start, end = sim_window(scenario)
    files = sorted(glob.glob(str(scenario / "gather" / host / "logs" / "apache2" / pattern)))
    if not files:
        sys.exit(f"no access logs matched {host}/logs/apache2/{pattern} under {scenario}")

    windows = defaultdict(new_web_window)
    steps = defaultdict(Counter)        # window key -> AIT label -> labelled lines
    stats = Counter()
    for f in files:
        rel = Path(f).relative_to(scenario / "gather")
        labels = load_labels(scenario / "labels" / rel)
        stats["labelled_lines_in_label_files"] += len(labels)
        with open(f, encoding="utf-8", errors="replace") as fh:
            for lineno, raw in enumerate(fh, start=1):
                lab = labels.get(lineno)
                m = LINE_RE.match(raw)
                if not m:
                    stats["skipped_unparsed"] += 1
                    stats["skipped_labelled"] += bool(lab)
                    continue
                ts = datetime.strptime(m["ts"], "%d/%b/%Y:%H:%M:%S %z").astimezone(timezone.utc)
                if not (start <= ts < end):
                    stats["outside_simulation"] += 1
                    stats["skipped_labelled"] += bool(lab)
                    continue
                req = REQ_RE.match(m["req"])
                if not req:
                    stats["skipped_bad_request"] += 1
                    stats["skipped_labelled"] += bool(lab)
                    continue
                key = window_key(ts)
                fold_web(windows[key], req["url"], req["method"], m["status"], m["ip"])
                stats["requests"] += 1
                if lab:
                    stats["labelled_requests"] += 1
                    steps[key].update(lab)

    rows = []
    for key, w in windows.items():
        row = web_row(key, w)
        n_attack = max(steps[key].values(), default=0)
        rows.append({
            "timestamp": row["timestamp"].isoformat(),
            **{f: row[f] for f in WEB_FEATURES},
            "injection": row["injection"],
            "traversal": row["traversal"],
            "label": int(bool(steps[key])),
            "attack_lines": n_attack,
            "steps": ";".join(sorted(steps[key])),
            "top_ips": ";".join(f"{ip}:{n}" for ip, n in row["top_ips"]),
        })
    df = pd.DataFrame(rows).sort_values("timestamp").reset_index(drop=True)
    meta = {
        "scenario": scenario.name, "lane": "web", "host": host,
        "sim_start": start.isoformat(), "sim_end": end.isoformat(),
        "files": [str(Path(f).relative_to(scenario)) for f in files],
        "windows": len(df), "attack_windows": int(df["label"].sum()),
        **dict(stats),
    }
    return df, meta


def main():
    ap = argparse.ArgumentParser(description=__doc__.split("\n\n")[0])
    ap.add_argument("scenario", type=Path, help="unzipped AIT scenario directory")
    ap.add_argument("-o", "--out", type=Path, required=True, help="output CSV")
    ap.add_argument("--host", default="intranet_server")
    ap.add_argument("--pattern", default="intranet.*-access.log*")
    a = ap.parse_args()

    df, meta = build(a.scenario.resolve(), a.host, a.pattern)
    os.makedirs(a.out.parent, exist_ok=True)
    df.to_csv(a.out, index=False)
    Path(str(a.out) + ".meta.json").write_text(json.dumps(meta, indent=2), encoding="utf-8")
    print(json.dumps(meta, indent=2))


if __name__ == "__main__":
    main()
