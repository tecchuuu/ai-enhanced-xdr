import { EuiFlexGroup, EuiFlexItem, EuiPanel, EuiStat } from "@elastic/eui";
import { COLOR_RULE, COLOR_AI } from "./badges";

export default function StatPanels({ stats, combined }) {
  const ruleCount = stats?.rule_alerts ?? "—";
  const aiCount = stats?.ai_alerts ?? "—";

  // windows where the model fired and no rule did (computed from the merged feed)
  let modelOnly = "—";
  if (combined?.alerts) {
    const ruleMinutes = new Set(
      combined.alerts
        .filter((a) => a.source !== "ai" && a.timestamp)
        .map((a) => a.timestamp.slice(0, 16))
    );
    modelOnly = combined.alerts.filter(
      (a) => a.source === "ai" && a.timestamp && !ruleMinutes.has(a.timestamp.slice(0, 16))
    ).length;
  }

  const items = [
    { title: ruleCount, description: "Rule alerts", color: COLOR_RULE },
    { title: aiCount, description: "AI detections", color: COLOR_AI },
    { title: modelOnly, description: "Model-only catches", color: "#bd271e" },
    { title: stats?.by_level ? Object.keys(stats.by_level).length : "—", description: "Distinct severity levels", color: "default" },
  ];

  return (
    <EuiFlexGroup>
      {items.map((it) => (
        <EuiFlexItem key={it.description}>
          <EuiPanel hasBorder>
            <EuiStat
              title={String(it.title)}
              description={it.description}
              titleColor={it.color}
              titleSize="l"
            />
          </EuiPanel>
        </EuiFlexItem>
      ))}
    </EuiFlexGroup>
  );
}
