import { useState } from "react";
import { EuiPanel, EuiSpacer, EuiCallOut, EuiFlexGroup, EuiFlexItem, EuiText } from "@elastic/eui";
import { getAiAlerts } from "../api";
import { usePolling } from "../lib/usePolling";
import { scopeParams, scopeDeps } from "../lib/scope";
import { usePalette } from "../theme/ThemeProvider";
import AlertsTable from "../components/AlertsTable";
import HBarChart from "../components/HBarChart";
import FeedSearch from "../components/FeedSearch";
import PipelineNotice from "../components/PipelineNotice";

const LIMIT = 200;

// detections written before the August enrichment carry no category
const categoryLabel = (c) => (c ? c.replace(/_/g, " ") : "no category");

export default function AiDetections({ scope }) {
  const p = usePalette();
  const [q, setQ] = useState("");
  const [data, setData] = useState(null);
  const [error, setError] = useState(null);

  usePolling(
    async (isCurrent) => {
      try {
        const d = await getAiAlerts({ limit: LIMIT, q, ...scopeParams(scope) });
        if (!isCurrent()) return;
        setData(d);
        setError(null);
      } catch (e) {
        if (isCurrent()) setError(String(e.message ?? e));
      }
    },
    15000,
    [q, ...scopeDeps(scope)]
  );

  const alerts = data?.alerts ?? [];

  // counted from the loaded detections, so the chart describes the table below it
  const counts = {};
  for (const a of alerts) {
    const label = categoryLabel(a.category);
    counts[label] = (counts[label] ?? 0) + 1;
  }
  const categories = Object.entries(counts)
    .map(([label, count]) => ({ label, count }))
    .sort((a, b) => b.count - a.count);

  return (
    <>
      <PipelineNotice />
      <HBarChart
        title="Detections by category"
        info="Heuristic post-classification of the detections below. The model flags the deviation; the category makes it triageable."
        data={categories}
        seriesName="Detections"
        color={p.ai}
        empty={{
          icon: "chartBarVertical",
          title: "No detections in this range",
          body: "Widen the time range, or generate traffic and give the consumer ~10 minutes to fill its window buffer.",
        }}
      />
      <EuiSpacer />
      <EuiPanel hasBorder>
        <EuiFlexGroup gutterSize="s" alignItems="center" responsive={false} wrap>
          <EuiFlexItem style={{ minWidth: 260 }}>
            <FeedSearch
              placeholder="Search IP, URL, category or text, then Enter"
              onSearch={(v) => {
                setQ(v);
                setData(null);
              }}
            />
          </EuiFlexItem>
          {data && (
            <EuiFlexItem grow={false}>
              <EuiText size="xs" color="subdued">
                Latest {alerts.length} of {data.count.toLocaleString()}
              </EuiText>
            </EuiFlexItem>
          )}
        </EuiFlexGroup>
        <EuiSpacer size="s" />
        {error && (
          <>
            <EuiCallOut title={`AI detections unavailable: ${error}`} color="danger" size="s" />
            <EuiSpacer size="s" />
          </>
        )}
        <AlertsTable
          alerts={alerts}
          loading={data == null && !error}
          showScore
          showSource={false}
        />
      </EuiPanel>
    </>
  );
}
