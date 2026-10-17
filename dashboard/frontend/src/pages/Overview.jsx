import { useState } from "react";
import {
  EuiSpacer,
  EuiTitle,
  EuiPanel,
  EuiText,
  EuiFlexGroup,
  EuiFlexItem,
  EuiButtonGroup,
} from "@elastic/eui";
import { getHistogram, getTopSrcIps, getMetrics, getCombined } from "../api";
import { usePolling } from "../lib/usePolling";
import { usePalette } from "../theme/ThemeProvider";
import StatPanels from "../components/StatPanels";
import AlertsTable from "../components/AlertsTable";
import AlertsOverTime from "../components/AlertsOverTime";
import HBarChart from "../components/HBarChart";

const RANGES = [
  { id: "6", label: "6h", interval: "10m" },
  { id: "24", label: "24h", interval: "30m" },
  { id: "168", label: "7d", interval: "3h" },
  { id: "720", label: "30d", interval: "12h" },
];

export default function Overview() {
  const p = usePalette();
  const [rangeId, setRangeId] = useState("24");
  const [metrics, setMetrics] = useState(null);
  const [buckets, setBuckets] = useState(null);
  const [ips, setIps] = useState(null);
  const [recent, setRecent] = useState(null);

  const range = RANGES.find((r) => r.id === rangeId);

  usePolling(
    async (isCurrent) => {
      try {
        const [m, h, t] = await Promise.all([
          getMetrics(Number(range.id)),
          getHistogram(Number(range.id), range.interval),
          getTopSrcIps(Number(range.id)),
        ]);
        if (!isCurrent()) return;
        setMetrics(m);
        setBuckets(h.buckets);
        setIps(t.ips.map((i) => ({ label: i.ip, count: i.count })));
      } catch {
        /* header health indicator already reports API problems */
      }
    },
    30000,
    [rangeId]
  );

  const refreshRecent = usePolling(async (isCurrent) => {
    try {
      const c = await getCombined(10);
      if (isCurrent()) setRecent(c.alerts);
    } catch {
      /* as above */
    }
  }, 15000);

  return (
    <>
      <StatPanels metrics={metrics} hours={range.label} />
      <EuiSpacer />
      <EuiFlexGroup justifyContent="flexEnd" responsive={false}>
        <EuiFlexItem grow={false}>
          <EuiButtonGroup
            legend="Time range"
            options={RANGES.map(({ id, label }) => ({ id, label }))}
            idSelected={rangeId}
            onChange={setRangeId}
            buttonSize="compressed"
          />
        </EuiFlexItem>
      </EuiFlexGroup>
      <EuiSpacer size="s" />
      <EuiFlexGroup>
        <EuiFlexItem grow={2}>
          <AlertsOverTime buckets={buckets} hours={range.label} />
        </EuiFlexItem>
        <EuiFlexItem grow={1}>
          <HBarChart
            title="Top source IPs"
            description={`Most active alert sources, last ${range.label}.`}
            data={ips}
            seriesName="Alerts"
            color={p.single}
            empty={{
              icon: "globe",
              title: "No source IPs yet",
              body: `No alerts carrying a source IP in the last ${range.label}. Attacks from another host will populate this; loopback traffic will not.`,
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
            Most recent from both streams (rules at level 10+). Full feeds under Security
            events and AI detections.
          </p>
        </EuiText>
        <EuiSpacer size="s" />
        <AlertsTable alerts={recent ?? []} loading={recent == null} onRefresh={refreshRecent} />
      </EuiPanel>
    </>
  );
}
