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
import { scopeParams, scopeDeps } from "../lib/scope";
import AlertsTable from "../components/AlertsTable";
import FeedSearch from "../components/FeedSearch";

// Wazuh severity tiers (severityName in badges.jsx). "All levels" is the
// default, as in Wazuh's own events view.
const LEVELS = [
  { id: "0", label: "All levels" },
  { id: "7", label: "7+" },
  { id: "10", label: "10+" },
  { id: "12", label: "12+" },
];
const LIMIT = 200;

// OpenSearch stops counting at 10,000 unless asked to track the exact total
const fmtTotal = (n) => (n >= 10000 ? "10,000+" : n.toLocaleString());

export default function SecurityEvents({ scope }) {
  const [minLevel, setMinLevel] = useState("0");
  const [q, setQ] = useState("");
  const [data, setData] = useState(null);
  const [error, setError] = useState(null);

  usePolling(
    async (isCurrent) => {
      try {
        const d = await getRuleAlerts({ limit: LIMIT, min_level: minLevel, q, ...scopeParams(scope) });
        if (!isCurrent()) return;
        setData(d);
        setError(null);
      } catch (e) {
        if (isCurrent()) setError(String(e.message ?? e));
      }
    },
    15000,
    [minLevel, q, ...scopeDeps(scope)]
  );

  return (
    <EuiPanel hasBorder>
      <EuiFlexGroup gutterSize="s" alignItems="center" responsive={false} wrap>
        <EuiFlexItem style={{ minWidth: 260 }}>
          <FeedSearch
            placeholder="Search IP, user, rule ID or text, then Enter"
            onSearch={(v) => {
              setQ(v);
              setData(null);
            }}
          />
        </EuiFlexItem>
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
              Latest {data.alerts.length} of {fmtTotal(data.count)}
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
      />
    </EuiPanel>
  );
}
