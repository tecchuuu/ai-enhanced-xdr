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
import { getRuleAlerts, getBreakdown } from "../api";
import { usePolling } from "../lib/usePolling";
import { usePagedFeed } from "../lib/usePagedFeed";
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

// The same layout as the AI detections page — chart, filters, table — so the
// two sides of the console read the same way. Both the chart and the table
// cover every alert matching the filters, not just the page on screen.
export default function WazuhAlerts({ scope }) {
  const p = usePalette();
  const [minLevel, setMinLevel] = useState("0");
  const [q, setQ] = useState("");
  const [rules, setRules] = useState(null);
  const { data, error, server } = usePagedFeed(getRuleAlerts, { min_level: minLevel, q }, scope);

  usePolling(
    async (isCurrent) => {
      try {
        const b = await getBreakdown({ source: "rule", min_level: minLevel, q, ...scopeParams(scope) });
        if (isCurrent()) setRules(b.items);
      } catch {
        /* the table reports API problems */
      }
    },
    30000,
    [minLevel, q, ...scopeDeps(scope)]
  );

  return (
    <>
      <HBarChart
        title="Alerts by rule"
        info="Which Wazuh rules fired most, counted over every alert matching the level filter and search in this range — not just the page shown below."
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
            <FeedSearch placeholder="Search IP, user, rule or text, then Enter" onSearch={setQ} />
          </EuiFlexItem>
          <EuiFlexItem grow={false}>
            <EuiButtonGroup
              legend="Minimum rule level"
              options={LEVELS}
              idSelected={minLevel}
              onChange={setMinLevel}
              buttonSize="compressed"
            />
          </EuiFlexItem>
          {data && (
            <EuiFlexItem grow={false}>
              <EuiText size="xs" color="subdued">
                {data.count.toLocaleString()} alert{data.count === 1 ? "" : "s"}
                {data.count > 10000 && " — the newest 10,000 can be paged through; narrow the range for the rest"}
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
        <AlertsTable
          alerts={data?.alerts ?? []}
          loading={data == null && !error}
          showSource={false}
          server={server}
        />
      </EuiPanel>
    </>
  );
}
