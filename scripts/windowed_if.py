import json, pandas as pd, numpy as np
from sklearn.ensemble import IsolationForest

# ---------- 1. Load raw events (incl. rule id, for the rule-vs-AI comparison) ----------
rows = []
with open("/home/magi/root-backup/archive_18.json") as f:
    for line in f:
        try:
            e = json.loads(line)
        except json.JSONDecodeError:
            continue
        d = e.get("data", {})
        if "srcip" not in d:
            continue
        r = e.get("rule", {})
        rows.append({
            "timestamp": e.get("timestamp"),
            "rule_id":   r.get("id"),
            "level":     r.get("level", 0),
            "srcuser":   d.get("srcuser"),
        })

df = pd.DataFrame(rows)
df["timestamp"] = pd.to_datetime(df["timestamp"])
df = df.set_index("timestamp").sort_index()
print(f"Loaded {len(df)} auth events "
      f"({df.index.min()} -> {df.index.max()})\n")

# ---------- 2. FEATURE ENGINEERING: aggregate into 1-minute windows ----------
# Empty windows are kept (fill 0) -> these are the "quiet/normal" baseline.
w = df.resample("1min").agg(
    event_count    = ("rule_id", "size"),
    distinct_users = ("srcuser", pd.Series.nunique),
    max_level      = ("level", "max"),
).fillna(0)

w["hour"] = w.index.hour
w["distinct_users"] = w["distinct_users"].fillna(0)
w["max_level"] = w["max_level"].fillna(0)

# did rule 5712 (brute force) fire in this window? -> the RULE-BASED baseline
fired = df[df["rule_id"] == "5712"].resample("1min").size()
w["rule_5712_fired"] = fired.reindex(w.index, fill_value=0).gt(0).astype(int)

print(f"Built {len(w)} one-minute windows "
      f"({(w.event_count == 0).sum()} quiet, {(w.event_count > 0).sum()} active)\n")

# ---------- 3. Isolation Forest on window behaviour ----------
FEATURES = ["event_count", "distinct_users", "max_level", "hour"]
model = IsolationForest(contamination=0.15, random_state=42)
w["ai_flag"] = (model.fit_predict(w[FEATURES]) == -1).astype(int)

# ---------- 4. Compare: rule-based vs AI ----------
active = w[w.event_count > 0]
print("=== ACTIVE WINDOWS (rule vs AI) ===")
print(active[FEATURES + ["rule_5712_fired", "ai_flag"]].to_string())

n_rule = int(active.rule_5712_fired.sum())
n_ai   = int(active.ai_flag.sum())
caught_only_by_ai = active[(active.ai_flag == 1) & (active.rule_5712_fired == 0)]

print(f"\n--- SUMMARY ---")
print(f"Active windows:                 {len(active)}")
print(f"Flagged by rule 5712:           {n_rule}")
print(f"Flagged by AI model:            {n_ai}")
print(f"Flagged by AI but NOT by rule:  {len(caught_only_by_ai)}  <-- the delta")
if len(caught_only_by_ai):
    print("\nWindows the rule missed but AI caught:")
    print(caught_only_by_ai[FEATURES].to_string())

w.to_csv("/home/magi/root-backup/windowed_features.csv")
print("\nSaved -> windowed_features.csv")
