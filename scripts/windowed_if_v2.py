"""
Windowed anomaly detection on real Wazuh auth events.

v2 changes vs v1:
  - FIX: distinct-user counting no longer collapses to 0 for PAM/5503 events
         (user is recovered from full_log when the decoder didn't populate srcuser)
  - NEW: failure_ratio + events_per_user features (volume-independent -> slow-attack aware)
  - NEW: WINDOW is configurable; run it at several scales (multi-scale windowing:
         short windows catch bursts, long windows catch low-and-slow)
"""

import json, re, sys
import pandas as pd
from sklearn.ensemble import IsolationForest

ARCHIVE = "/root/archive_18.json"
WINDOW = sys.argv[1] if len(sys.argv) > 1 else "5min"   # e.g. python windowed_if_v2.py 10min
CONTAMINATION = 0.2

# ---------------------------------------------------------------- 1. load events
USER_RE = re.compile(r"(?:invalid user |user )([A-Za-z0-9_.-]+)")

rows = []
with open(ARCHIVE) as f:
    for line in f:
        try:
            e = json.loads(line)
        except json.JSONDecodeError:
            continue
        d = e.get("data", {})
        if "srcip" not in d:
            continue
        r = e.get("rule", {})

        # FIX: recover the username when the decoder didn't fill srcuser (e.g. PAM 5503)
        user = d.get("srcuser")
        if not user:
            m = USER_RE.search(e.get("full_log", "") or "")
            user = m.group(1) if m else None

        rows.append({
            "timestamp": e.get("timestamp"),
            "rule_id":   r.get("id"),
            "level":     r.get("level", 0),
            "srcuser":   user,
        })

df = pd.DataFrame(rows)
df["timestamp"] = pd.to_datetime(df["timestamp"])
df = df.set_index("timestamp").sort_index()

span_min = (df.index.max() - df.index.min()).total_seconds() / 60
print(f"Loaded {len(df)} auth events spanning {span_min:.1f} minutes")
print(f"  {df.index.min()}  ->  {df.index.max()}")
print(f"  users recovered: {df.srcuser.notna().sum()}/{len(df)} "
      f"({df.srcuser.nunique()} distinct)\n")

# ---------------------------------------------------------------- 2. windowed features
w = df.resample(WINDOW).agg(
    event_count    = ("rule_id", "size"),
    distinct_users = ("srcuser", "nunique"),   # now counts recovered users too
    max_level      = ("level", "max"),
).fillna(0)

w["hour"] = w.index.hour
# volume-independent signals: these are what expose a SLOW attack
w["events_per_user"] = (w.event_count / w.distinct_users.replace(0, 1)).round(2)
w["user_diversity"]  = (w.distinct_users / w.event_count.replace(0, 1)).round(2)

# rule-based baseline: did brute-force rule 5712 fire in this window?
fired = df[df.rule_id == "5712"].resample(WINDOW).size()
w["rule_5712"] = fired.reindex(w.index, fill_value=0).gt(0).astype(int)

n_active = int((w.event_count > 0).sum())
print(f"Window size: {WINDOW}  ->  {len(w)} windows ({n_active} active, "
      f"{len(w) - n_active} quiet)")

if len(w) < 10:
    print(f"  !! WARNING: only {len(w)} windows. Isolation Forest needs more samples")
    print(f"     to be meaningful. Generate a longer traffic run (see notes).\n")
else:
    print()

# ---------------------------------------------------------------- 3. isolation forest
FEATURES = ["event_count", "distinct_users", "max_level",
            "hour", "events_per_user", "user_diversity"]

model = IsolationForest(contamination=CONTAMINATION, random_state=42)
w["ai_flag"] = (model.fit_predict(w[FEATURES]) == -1).astype(int)

# ---------------------------------------------------------------- 4. rule vs AI
active = w[w.event_count > 0]
print("=== ACTIVE WINDOWS ===")
print(active[FEATURES + ["rule_5712", "ai_flag"]].to_string())

only_ai   = active[(active.ai_flag == 1) & (active.rule_5712 == 0)]
only_rule = active[(active.ai_flag == 0) & (active.rule_5712 == 1)]

print(f"\n--- SUMMARY ({WINDOW} windows) ---")
print(f"Active windows:                {len(active)}")
print(f"Flagged by rule 5712:          {int(active.rule_5712.sum())}")
print(f"Flagged by AI model:           {int(active.ai_flag.sum())}")
print(f"AI caught, rule MISSED:        {len(only_ai)}   <-- Claim B delta")
print(f"Rule caught, AI missed:        {len(only_rule)}")

if len(only_ai):
    print("\nWindows the rule missed but the model flagged:")
    print(only_ai[FEATURES].to_string())

out = f"/root/windowed_{WINDOW}.csv"
w.to_csv(out)
print(f"\nSaved -> {out}")
