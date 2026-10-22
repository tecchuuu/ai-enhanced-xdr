import { useState } from "react";
import { EuiPanel, EuiSpacer, EuiCallOut, EuiFlexGroup, EuiFlexItem, EuiText } from "@elastic/eui";
import { getAiAlerts } from "../api";
import { usePolling } from "../lib/usePolling";
import { scopeParams, scopeDeps } from "../lib/scope";
import { usePalette } from "../theme/ThemeProvider";
import AlertsTable from "../components/AlertsTable";
import HBarChart from "../components/HBarChart";
import FeedSearch from "../components/FeedSearch";

const LIMIT = 200;

// detections written before the August enrichment carry no category
const categoryLabel = (c) => (c ? c.replace(/_/g, " ") : "no type");

// Same layout as the Wazuh alerts page: chart, filters, table.
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
      <HBarChart
        title="Detections by attack type"
        info="The likely attack type of the detections listed below, assigned by simple rules after the model has flagged the minute. The model finds the unusual activity; the type helps decide what to do about it."
        data={categories}
        seriesName="Detections"
        color={p.ai}
        empty={{
          icon: "chartBarHorizontal",
          title: "No detections in this range",
          body: "Widen the time range, or generate traffic. Each detector needs about 10 minutes of activity before it starts flagging.",
        }}
      />
      <EuiSpacer />
      <EuiPanel hasBorder>
        <EuiFlexGroup gutterSize="s" alignItems="center" responsive={false} wrap>
          <EuiFlexItem style={{ minWidth: 260 }}>
            <FeedSearch
              placeholder="Search IP, URL, attack type or text, then Enter"
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
        <AlertsTable alerts={alerts} loading={data == null && !error} showScore showSource={false} />
      </EuiPanel>
    </>
  );
}
