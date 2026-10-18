import {
  EuiFlexGroup,
  EuiFlexItem,
  EuiPanel,
  EuiStat,
  EuiText,
  EuiIconTip,
} from "@elastic/eui";
import { usePalette } from "../theme/ThemeProvider";
import Dot from "./Dot";

// Fed by /api/metrics for the header's range and agent, so these are the same
// numbers the Metrics page shows for that scope — one definition of each.
export default function StatPanels({ metrics }) {
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
              <p>{allLevels.toLocaleString()} at all levels in this range.</p>
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
                Minutes AI-only (rules silent){" "}
                <EuiIconTip
                  type="info"
                  color="subdued"
                  aria-label="About AI-only minutes"
                  content="Minutes in this range where the model flagged a window and no level 10+ rule fired — what signature detection missed."
                />
              </>
            }
          />
        </EuiPanel>
      </EuiFlexItem>
    </EuiFlexGroup>
  );
}
