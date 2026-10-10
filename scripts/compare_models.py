#!/usr/bin/env python3
"""Offline comparison: Isolation Forest vs Autoencoder on the same windowed
auth features. Fills the บทที่ 4 "autoencoder vs Isolation Forest" gap.

Uses the SAME model registry the live pipeline uses (ai-stack/pipeline/models),
so this compares the actual inference-slot implementations, not throwaway copies.

Run:  ml-venv/bin/python scripts/compare_models.py [windowed_features.csv]
"""
import sys
from pathlib import Path
import pandas as pd

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "ai-stack" / "pipeline"))
from models import get_model  # noqa: E402

CSV = sys.argv[1] if len(sys.argv) > 1 else str(ROOT / "data" / "windowed_features.csv")
CONTAM = 0.15
FEATURES = ["event_count", "distinct_users", "max_level", "hour", "events_per_user"]

df = pd.read_csv(CSV)
if "events_per_user" not in df.columns:
    df["events_per_user"] = df["event_count"] / df["distinct_users"].replace(0, 1)
X = df[FEATURES].fillna(0)
rule = df["rule_5712_fired"].astype(int) if "rule_5712_fired" in df.columns else None

flagged = {}
devices = {}
for name in ("isolation_forest", "autoencoder"):
    m = get_model(name)
    flags, scores = m.fit_score(X, CONTAM)
    df[f"{name}_flag"] = flags
    flagged[name] = (flags == -1)
    # report the hardware each slot actually ran on (the autoencoder picks up CUDA if present)
    devices[name] = (f"{m.last_device}, fit {m.last_fit_sec}s"
                     if getattr(m, "last_device", None) else "cpu (scikit-learn)")

print(f"Dataset: {CSV}  ({len(df)} windows, contamination={CONTAM})\n")
if rule is not None:
    print(f"Rule 5712 (brute-force declaration) fired in {int(rule.sum())} window(s)\n")

for name in ("isolation_forest", "autoencoder"):
    f = flagged[name]
    line = f"{name:16s}: flagged {int(f.sum()):2d}"
    line += f"  | ran on: {devices[name]}"
    if rule is not None:
        line += f"  | agree w/ rule: {int((f & (rule == 1)).sum())}  | model-only: {int((f & (rule == 0)).sum())}"
    print(line)

iff, aef = flagged["isolation_forest"], flagged["autoencoder"]
print(f"\nModel agreement:  both={int((iff & aef).sum())}  IF-only={int((iff & ~aef).sum())}  AE-only={int((aef & ~iff).sum())}")

print("\nPer-window  (ev=event_count du=distinct_users | rule / IF / AE):")
m = lambda b: "X" if b else "."
for _, r in df.iterrows():
    ts = str(r.get("timestamp", ""))[:19]
    rr = m(int(r.get("rule_5712_fired", 0)) == 1) if rule is not None else "?"
    print(f"  {ts}  ev={int(r.event_count):3d} du={int(r.distinct_users)}  "
          f"rule={rr}  IF={m(r.isolation_forest_flag == -1)}  AE={m(r.autoencoder_flag == -1)}")
