import { useState } from "react";
import { EuiSpacer, EuiTitle, EuiPanel, EuiText, EuiFlexGroup, EuiFlexItem } from "@elastic/eui";
import { getHistogram, getTopSrcIps, getMetrics, getCombined } from "../api";
import { usePolling } from "../lib/usePolling";
import { scopeParams, scopeDeps } from "../lib/scope";
import { useOpenIp } from "../lib/ipContext";
import { usePalette } from "../theme/ThemeProvider";
import StatPanels from "../components/StatPanels";
import AlertsTable from "../components/AlertsTable";
import AlertsOverTime from "../components/AlertsOverTime";
import HBarChart from "../components/HBarChart";

export default function Overview({ scope }) {
  const p = usePalette();
  const openIp = useOpenIp();
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

  const refreshRecent = usePolling(
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
          <HBarChart
            title="Top source IPs"
            description="Most active alert sources in this range. Click a bar to investigate the IP."
            data={ips}
            seriesName="Alerts"
            color={p.single}
            onBarClick={openIp}
            empty={{
              icon: "globe",
              title: "No source IPs yet",
              body: "No alerts carrying a source IP in this range. Attacks from another host will populate this; loopback traffic will not.",
            }}
          />
        </EuiFlexItem>
      </EuiFlexGroup>
      <EuiSpacer />
      <EuiPanel hasBorder>
        <EuiTitle size="xs">
          <h2>Latest detections</h2>
        </EuiTitle>
        <EuiText size="s" color="subdued">
          <p>
            Most recent from both streams in this range (rules at level 10+). Full feeds
            under Security events and AI detections.
          </p>
        </EuiText>
        <EuiSpacer size="s" />
        <AlertsTable
          alerts={recent ?? []}
          loading={recent == null}
          showTriageFilter={false}
          onRefresh={refreshRecent}
        />
      </EuiPanel>
    </>
  );
}
