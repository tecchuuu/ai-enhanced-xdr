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

// Fed by /api/metrics for the Overview's selected range, so these are the same
// numbers the Metrics page shows for that range — one definition of each.
export default function StatPanels({ metrics, hours }) {
  const p = usePalette();
  const ruleCount = metrics?.rule_alerts ?? "—";
  const allLevels = metrics?.rule_alerts_all_levels;
  const aiCount = metrics?.ai_detections ?? "—";
  const aiOnly = metrics?.overlap_minutes?.ai_only ?? "—";

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
                Rule alerts (level 10+)
              </>
            }
          />
          {allLevels != null && (
            <EuiText size="xs" color="subdued">
              <p>{allLevels.toLocaleString()} at all levels, last {hours}.</p>
            </EuiText>
          )}
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
            title={String(aiOnly)}
            titleSize="l"
            titleColor="default"
            description={
              <>
                <Dot color={p.ai} />
                Minutes AI-only (rules silent)
              </>
            }
          />
          <EuiText size="xs" color="subdued">
            <p>
              Minutes, last {hours}, where the model flagged a window and no
              level 10+ rule fired — what signature detection missed.
            </p>
          </EuiText>
        </EuiPanel>
      </EuiFlexItem>
    </EuiFlexGroup>
  );
}
