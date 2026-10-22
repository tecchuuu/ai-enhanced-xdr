import { EuiFlexGroup, EuiFlexItem, EuiPanel, EuiStat, EuiText, EuiIconTip } from "@elastic/eui";
import { usePalette } from "../theme/ThemeProvider";
import Dot from "./Dot";

// One headline tile. `note` is a short line under the number; `info` the
// longer explanation, one hover away.
export function Tile({ value, label, dot, note, info, size = "m" }) {
  return (
    <EuiPanel hasBorder paddingSize="m">
      <EuiStat
        title={value == null ? "—" : String(value)}
        titleSize={size}
        titleColor="default"
        description={
          <>
            {dot && <Dot color={dot} />}
            {label}
            {info && (
              <>
                {" "}
                <EuiIconTip type="info" color="subdued" aria-label={`About: ${label}`} content={info} />
              </>
            )}
          </>
        }
      />
      {note && (
        <EuiText size="xs" color="subdued">
          <p>{note}</p>
        </EuiText>
      )}
    </EuiPanel>
  );
}

export const ONLY_AI_INFO =
  "AI detections in minutes when no Wazuh rule at level 10 or above fired. This is where the two disagree — worth a look, but not proof that the rules missed an attack: the AI can be wrong too. Accuracy is measured in the evaluation, where the true attacks are known.";

// Fed by /api/metrics for the header's range and agent, so these are the same
// numbers the Rules vs AI page shows for that scope — one definition of each.
export default function StatPanels({ metrics }) {
  const p = usePalette();
  const allLevels = metrics?.rule_alerts_all_levels;

  return (
    <EuiFlexGroup gutterSize="m" alignItems="stretch">
      <EuiFlexItem>
        <Tile
          value={metrics?.rule_alerts}
          label="Wazuh alerts (level 10+)"
          dot={p.rule}
          note={allLevels != null ? `${allLevels.toLocaleString()} at all levels` : null}
        />
      </EuiFlexItem>
      <EuiFlexItem>
        <Tile value={metrics?.ai_detections} label="AI detections" dot={p.ai} />
      </EuiFlexItem>
      <EuiFlexItem>
        <Tile
          value={metrics?.ai_only_detections}
          label="Flagged only by AI"
          dot={p.ai}
          note="no Wazuh alert in the same minute"
          info={ONLY_AI_INFO}
          size="l"
        />
      </EuiFlexItem>
    </EuiFlexGroup>
  );
}
