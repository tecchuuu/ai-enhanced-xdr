import {
  EuiFlexGroup,
  EuiFlexItem,
  EuiPanel,
  EuiStat,
  EuiText,
} from "@elastic/eui";
import { usePalette } from "../theme/ThemeProvider";

// Numbers wear text ink; a small colored dot beside the label carries identity.
// Painting four large figures in saturated series colors makes none of them
// stand out — the color has to be scarce to mean anything.
function Dot({ color }) {
  return (
    <span
      aria-hidden="true"
      style={{
        display: "inline-block",
        width: 8,
        height: 8,
        borderRadius: "50%",
        background: color,
        marginRight: 6,
        verticalAlign: "middle",
      }}
    />
  );
}

export default function StatPanels({ stats, combined }) {
  const p = usePalette();
  const ruleCount = stats?.rule_alerts ?? "—";
  const aiCount = stats?.ai_alerts ?? "—";

  // windows where the model fired and no rule did (computed from the merged feed)
  let modelOnly = "—";
  if (combined?.alerts) {
    const ruleMinutes = new Set(
      combined.alerts
        .filter((a) => a.source !== "ai" && a.timestamp)
        .map((a) => a.timestamp.slice(0, 16)),
    );
    modelOnly = combined.alerts.filter(
      (a) =>
        a.source === "ai" &&
        a.timestamp &&
        !ruleMinutes.has(a.timestamp.slice(0, 16)),
    ).length;
  }

  return (
    <EuiFlexGroup gutterSize="m" alignItems="stretch">
      <EuiFlexItem>
        <EuiPanel hasBorder paddingSize="m">
          <EuiStat
            title={String(ruleCount)}
            titleSize="m"
            titleColor="default"
            description={
              <>
                <Dot color={p.rule} />
                Rule alerts
              </>
            }
          />
        </EuiPanel>
      </EuiFlexItem>

      <EuiFlexItem>
        <EuiPanel hasBorder paddingSize="m">
          <EuiStat
            title={String(aiCount)}
            titleSize="m"
            titleColor="default"
            description={
              <>
                <Dot color={p.ai} />
                AI detections
              </>
            }
          />
        </EuiPanel>
      </EuiFlexItem>

      {/* the headline: this number is the argument the project exists to make */}
      <EuiFlexItem>
        <EuiPanel hasBorder paddingSize="m">
          <EuiStat
            title={String(modelOnly)}
            titleSize="l"
            titleColor="default"
            description={
              <>
                <Dot color={p.ai} />
                Model-only catches
              </>
            }
          />
          <EuiText size="xs" color="subdued">
            <p>
              Windows the model flagged with no rule alert in the same minute —
              what signature detection missed.
            </p>
          </EuiText>
        </EuiPanel>
      </EuiFlexItem>
    </EuiFlexGroup>
  );
}
