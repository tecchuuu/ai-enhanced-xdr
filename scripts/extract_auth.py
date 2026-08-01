import json, pandas as pd

rows = []
with open("/root/archive_18.json") as f:
    for line in f:
        try:
            e = json.loads(line)
        except json.JSONDecodeError:
            continue
        d = e.get("data", {})
        # keep only decoded auth-failure events that have a source IP
        if "srcip" not in d:
            continue
        rule = e.get("rule", {})
        rows.append({
            "timestamp": e.get("timestamp"),
            "rule_id":   rule.get("id"),
            "level":     rule.get("level"),
            "srcip":     d.get("srcip"),
            "srcuser":   d.get("srcuser"),
            "desc":      rule.get("description"),
        })

df = pd.DataFrame(rows)
df["timestamp"] = pd.to_datetime(df["timestamp"])
print(f"Extracted {len(df)} auth events\n")
print(df.head(10).to_string())
print("\nRule ID counts:\n", df["rule_id"].value_counts())
print("\nUnique source IPs:", df["srcip"].nunique())
print("Unique users:", df["srcuser"].nunique())
df.to_csv("/root/auth_events.csv", index=False)
print("\nSaved -> auth_events.csv")
