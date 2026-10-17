import { useState } from "react";
import {
  EuiPanel,
  EuiSpacer,
  EuiButtonGroup,
  EuiFlexGroup,
  EuiFlexItem,
  EuiText,
  EuiCallOut,
} from "@elastic/eui";
import { getRuleAlerts } from "../api";
import { usePolling } from "../lib/usePolling";
import AlertsTable from "../components/AlertsTable";

// Wazuh severity tiers (severityName in badges.jsx). "All levels" is the
// default, as in Wazuh's own events view.
const LEVELS = [
  { id: "0", label: "All levels" },
  { id: "7", label: "7+" },
  { id: "10", label: "10+" },
  { id: "12", label: "12+" },
];
const LIMIT = 200;

export default function SecurityEvents() {
  const [minLevel, setMinLevel] = useState("0");
  const [data, setData] = useState(null);
  const [error, setError] = useState(null);

  const refresh = usePolling(
    async (isCurrent) => {
      try {
        const d = await getRuleAlerts(LIMIT, Number(minLevel));
        if (!isCurrent()) return;
        setData(d);
        setError(null);
      } catch (e) {
        if (isCurrent()) setError(String(e.message ?? e));
      }
    },
    15000,
    [minLevel]
  );

  // OpenSearch stops counting at 10,000 unless asked to track the exact total
  const total = data && (data.count >= 10000 ? "10,000+" : data.count.toLocaleString());

  return (
    <EuiPanel hasBorder>
      <EuiFlexGroup alignItems="center" justifyContent="spaceBetween" responsive={false}>
        <EuiFlexItem grow={false}>
          <EuiButtonGroup
            legend="Minimum rule level"
            options={LEVELS}
            idSelected={minLevel}
            onChange={(id) => {
              setMinLevel(id);
              setData(null);
            }}
            buttonSize="compressed"
          />
        </EuiFlexItem>
        {data && (
          <EuiFlexItem grow={false}>
            <EuiText size="xs" color="subdued">
              Latest {data.alerts.length} of {total}
            </EuiText>
          </EuiFlexItem>
        )}
      </EuiFlexGroup>
      <EuiSpacer size="s" />
      {error && (
        <>
          <EuiCallOut title={`Rule alerts unavailable: ${error}`} color="danger" size="s" />
          <EuiSpacer size="s" />
        </>
      )}
      <AlertsTable
        alerts={data?.alerts ?? []}
        loading={data == null && !error}
        showSource={false}
        onRefresh={refresh}
      />
    </EuiPanel>
  );
}
