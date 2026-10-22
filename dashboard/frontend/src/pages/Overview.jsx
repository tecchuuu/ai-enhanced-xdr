import { useState } from "react";
import { EuiSpacer, EuiPanel, EuiFlexGroup, EuiFlexItem } from "@elastic/eui";
import { getHistogram, getTopSrcIps, getMetrics, getCombined } from "../api";
import { usePolling } from "../lib/usePolling";
import { scopeParams, scopeDeps } from "../lib/scope";
import { useNav } from "../lib/nav";
import { usePalette } from "../theme/ThemeProvider";
import StatPanels from "../components/StatPanels";
import AlertsTable from "../components/AlertsTable";
import AlertsOverTime from "../components/AlertsOverTime";
import HBarChart from "../components/HBarChart";
import PanelTitle from "../components/PanelTitle";

export default function Overview({ scope }) {
  const p = usePalette();
  const { openIp } = useNav();
  const [metrics, setMetrics] = useState(null);
  const [hist, setHist] = useState(null);
  const [ips, setIps] = useState(null);
  const [recent, setRecent] = useState(null);

  usePolling(
    async (isCurrent) => {
      const s = scopeParams(scope);
      try {
        const [m, h, t] = await Promise.all([getMetrics(s), getHistogram(s), getTopSrcIps(s)]);
        if (!isCurrent()) return;
        setMetrics(m);
        setHist({ ...h, from: Date.parse(s.start), to: Date.parse(s.end) });
        setIps(t.ips.map((i) => ({ label: i.ip, count: i.count })));
      } catch {
        /* header health indicator already reports API problems */
      }
    },
    30000,
    scopeDeps(scope)
  );

  usePolling(
    async (isCurrent) => {
      try {
        const c = await getCombined({ limit: 10, ...scopeParams(scope) });
        if (isCurrent()) setRecent(c.alerts);
      } catch {
        /* as above */
      }
    },
    15000,
    scopeDeps(scope)
  );

  return (
    <>
      <StatPanels metrics={metrics} />
      <EuiSpacer />
      <EuiFlexGroup>
        <EuiFlexItem grow={2}>
          <AlertsOverTime
            buckets={hist?.buckets}
            interval={hist?.interval}
            from={hist?.from}
            to={hist?.to}
          />
        </EuiFlexItem>
        <EuiFlexItem grow={1}>
          {/* counted from Wazuh alerts at every level, so it wears the Wazuh color */}
          <HBarChart
            title="Top source IPs"
            info="The addresses behind the most Wazuh alerts in this range, at every level. Click a bar to see everything about that IP."
            data={ips}
            seriesName="Alerts"
            color={p.rule}
            onBarClick={openIp}
            empty={{
              icon: "globe",
              title: "No source IPs yet",
              body: "No alerts with a source IP in this range. Attacks from another machine will show here; traffic from the server itself will not.",
            }}
          />
        </EuiFlexItem>
      </EuiFlexGroup>
      <EuiSpacer />
      <EuiPanel hasBorder>
        <PanelTitle
          title="Latest alerts"
          info="The newest Wazuh alerts (level 10+) and AI detections together. The full lists are under Wazuh alerts and AI detections."
        />
        <EuiSpacer size="s" />
        <AlertsTable alerts={recent ?? []} loading={recent == null} showTriageFilter={false} />
      </EuiPanel>
    </>
  );
}
