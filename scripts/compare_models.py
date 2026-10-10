#!/usr/bin/env python3
"""Offline comparison of inference-slot models on the same windowed auth features.

Fills the บทที่ 4 "model comparison" gap. Uses the SAME registry the live
pipeline uses (ai-stack/pipeline/models), so this compares the actual
implementations the consumers would run, not throwaway copies.

Each model reports the hardware it ran on and its fit time, so a CPU run and a
GPU run of the same model are directly comparable.

  python scripts/compare_models.py                                  # IF + autoencoder
  python scripts/compare_models.py --models isolation_forest,autoencoder,morpheus_dfencoder
  python scripts/compare_models.py --csv path/to/windowed_features.csv

morpheus_dfencoder needs the Morpheus conda env (see models/morpheus_dfencoder.py);
in the plain venv it fails with an ImportError, which is reported per-model rather
than aborting the comparison.
"""
import argparse
import sys
from pathlib import Path

import pandas as pd

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "ai-stack" / "pipeline"))
from models import available, get_model  # noqa: E402

CONTAM = 0.15
FEATURES = ["event_count", "distinct_users", "max_level", "hour", "events_per_user"]

ap = argparse.ArgumentParser()
ap.add_argument("--csv", default=str(ROOT / "data" / "windowed_features.csv"))
ap.add_argument("--models", default="isolation_forest,autoencoder",
                help=f"comma-separated; registered: {','.join(available())}")
ap.add_argument("--contamination", type=float, default=CONTAM)
args = ap.parse_args()

names = [n.strip() for n in args.models.split(",") if n.strip()]

df = pd.read_csv(args.csv)
if "events_per_user" not in df.columns:
    df["events_per_user"] = df["event_count"] / df["distinct_users"].replace(0, 1)
X = df[FEATURES].fillna(0)
rule = df["rule_5712_fired"].astype(int) if "rule_5712_fired" in df.columns else None

print(f"Dataset: {args.csv}  ({len(df)} windows, contamination={args.contamination})")
if rule is not None:
    print(f"Rule 5712 (brute-force declaration) fired in {int(rule.sum())} window(s)")
print()

flagged, devices, failed = {}, {}, {}
for name in names:
    try:
        m = get_model(name)
        flags, _ = m.fit_score(X, args.contamination)
    except Exception as exc:                    # a missing env must not kill the run
        failed[name] = f"{type(exc).__name__}: {exc}"
        print(f"{name:20s}: SKIPPED — {failed[name]}")
        continue
    df[f"{name}_flag"] = flags
    flagged[name] = (df[f"{name}_flag"] == -1)
    devices[name] = (f"{m.last_device}, fit {m.last_fit_sec}s"
                     if getattr(m, "last_device", None) else "cpu (scikit-learn)")

for name, f in flagged.items():
    line = f"{name:20s}: flagged {int(f.sum()):2d}  | ran on: {devices[name]}"
    if rule is not None:
        line += (f"  | agree w/ rule: {int((f & (rule == 1)).sum())}"
                 f"  | model-only: {int((f & (rule == 0)).sum())}")
    print(line)

# pairwise agreement — how far the models actually differ, not just how many
# windows each flagged (equal counts can still disagree on which windows)
live = list(flagged)
if len(live) > 1:
    print("\nPairwise agreement:")
    for i, a in enumerate(live):
        for b in live[i + 1:]:
            fa, fb = flagged[a], flagged[b]
            print(f"  {a} vs {b}:  both={int((fa & fb).sum())}  "
                  f"{a}-only={int((fa & ~fb).sum())}  {b}-only={int((fb & ~fa).sum())}")

if live:
    header = "  ".join(n[:6].upper().ljust(6) for n in live)
    print(f"\nPer-window  (ev=event_count du=distinct_users | rule | {header}):")
    mark = lambda b: "X" if b else "."
    for idx, r in df.iterrows():
        ts = str(r.get("timestamp", ""))[:19]
        rr = mark(int(r.get("rule_5712_fired", 0)) == 1) if rule is not None else "?"
        cells = "  ".join(mark(flagged[n].iloc[idx]).ljust(6) for n in live)
        print(f"  {ts}  ev={int(r.event_count):3d} du={int(r.distinct_users)}  "
              f"rule={rr}  {cells}")
