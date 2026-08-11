import { EuiPanel, EuiSpacer, EuiText, EuiTitle } from "@elastic/eui";
import AlertsTable from "../components/AlertsTable";

export default function AiDetections({ combined, loading }) {
  const alerts = (combined?.alerts ?? []).filter((a) => a.source === "ai");
  return (
    <EuiPanel hasBorder>
      <EuiTitle size="xs">
        <h2>Anomaly-model detections</h2>
      </EuiTitle>
      <EuiText size="s" color="subdued">
        <p>
          Windows flagged by the AI pipeline (currently Isolation Forest — the model is
          swappable). These are behaviours the signature ruleset did not declare an attack.
        </p>
      </EuiText>
      <EuiSpacer size="s" />
      <AlertsTable alerts={alerts} loading={loading} showScore />
    </EuiPanel>
  );
}
