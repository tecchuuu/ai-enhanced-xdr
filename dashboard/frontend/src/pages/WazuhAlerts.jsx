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
import { usePalette } from "../theme/ThemeProvider";
import AlertsTable from "../components/AlertsTable";
import HBarChart from "../components/HBarChart";
import FeedSearch from "../components/FeedSearch";

// Minimum rule level. Medium/High/Critical are Wazuh's own severity bands
// (severityName in badges.jsx); 10+ is the level every rules-vs-AI comparison
// in this console counts from (ATTACK_LEVEL in main.py). "All levels" is the
// default, as in Wazuh's own alerts view.
const LEVELS = [
  { id: "0", label: "All levels" },
  { id: "7", label: "Medium+" },
  { id: "10", label: "Level 10+" },
  { id: "12", label: "High+" },
  { id: "15", label: "Critical" },
];
const LIMIT = 200;
const TOP_RULES = 8;

// OpenSearch stops counting at 10,000 unless asked to track the exact total
const fmtTotal = (n) => (n >= 10000 ? "10,000+" : n.toLocaleString());

// The same layout as the AI detections page — chart, filters, table — so the
// two sides of the console read the same way.
export default function WazuhAlerts({ scope }) {
  const p = usePalette();
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

  const alerts = data?.alerts ?? [];

  // counted from the loaded alerts, so the chart describes the table below it
  const counts = {};
  for (const a of alerts) {
    const label = a.description ?? `rule ${a.rule_id ?? "?"}`;
    counts[label] = (counts[label] ?? 0) + 1;
  }
  const rules = Object.entries(counts)
    .map(([label, count]) => ({ label, count }))
    .sort((a, b) => b.count - a.count)
    .slice(0, TOP_RULES);

  return (
    <>
      <HBarChart
        title="Alerts by rule"
        info="Which Wazuh rules fired most among the alerts listed below (the level filter and search apply)."
        data={rules}
        seriesName="Alerts"
        color={p.rule}
        empty={{
          icon: "chartBarHorizontal",
          title: "No alerts in this range",
          body: "Widen the time range or lower the level filter.",
        }}
      />
      <EuiSpacer />
      <EuiPanel hasBorder>
        <EuiFlexGroup gutterSize="s" alignItems="center" responsive={false} wrap>
          <EuiFlexItem style={{ minWidth: 260 }}>
            <FeedSearch
              placeholder="Search IP, user, rule or text, then Enter"
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
                Latest {alerts.length} of {fmtTotal(data.count)}
              </EuiText>
            </EuiFlexItem>
          )}
        </EuiFlexGroup>
        <EuiSpacer size="s" />
        {error && (
          <>
            <EuiCallOut title={`Wazuh alerts unavailable: ${error}`} color="danger" size="s" />
            <EuiSpacer size="s" />
          </>
        )}
        <AlertsTable alerts={alerts} loading={data == null && !error} showSource={false} />
      </EuiPanel>
    </>
  );
}
