import { useEffect, useState } from "react";
import {
  EuiSpacer,
  EuiTitle,
  EuiPanel,
  EuiText,
  EuiFlexGroup,
  EuiFlexItem,
  EuiButtonGroup,
} from "@elastic/eui";
import { getHistogram, getTopSrcIps } from "../api";
import StatPanels from "../components/StatPanels";
import AlertsTable from "../components/AlertsTable";
import AlertsOverTime from "../components/AlertsOverTime";
import TopSrcIps from "../components/TopSrcIps";

const RANGES = [
  { id: "6", label: "6h", interval: "10m" },
  { id: "24", label: "24h", interval: "30m" },
  { id: "168", label: "7d", interval: "3h" },
  { id: "720", label: "30d", interval: "12h" },
];

export default function Overview({ stats, combined, loading }) {
  const [rangeId, setRangeId] = useState("24");
  const [buckets, setBuckets] = useState(null);
  const [ips, setIps] = useState(null);

  const range = RANGES.find((r) => r.id === rangeId);

  useEffect(() => {
    let alive = true;
    const load = async () => {
      try {
        const [h, t] = await Promise.all([
          getHistogram(Number(range.id), range.interval),
          getTopSrcIps(Number(range.id)),
        ]);
        if (!alive) return;
        setBuckets(h.buckets);
        setIps(t.ips);
      } catch {
        /* header health indicator already reports API problems */
      }
    };
    load();
    const t = setInterval(load, 30000);
    return () => {
      alive = false;
      clearInterval(t);
    };
  }, [range]);

  const recent = (combined?.alerts ?? []).slice(0, 10);

  return (
    <>
      <StatPanels stats={stats} combined={combined} />
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
          <TopSrcIps ips={ips} hours={range.label} />
        </EuiFlexItem>
      </EuiFlexGroup>
      <EuiSpacer />
      <EuiPanel hasBorder>
        <EuiTitle size="xs">
          <h2>Latest detections</h2>
        </EuiTitle>
        <EuiText size="s" color="subdued">
          <p>Most recent events from both streams. Full feed under Security events.</p>
        </EuiText>
        <EuiSpacer size="s" />
        <AlertsTable alerts={recent} loading={loading} />
      </EuiPanel>
    </>
  );
}
