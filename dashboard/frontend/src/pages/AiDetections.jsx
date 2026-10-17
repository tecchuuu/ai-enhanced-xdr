import { useState } from "react";
import { EuiPanel, EuiSpacer, EuiCallOut } from "@elastic/eui";
import { getAiAlerts } from "../api";
import { usePolling } from "../lib/usePolling";
import { usePalette } from "../theme/ThemeProvider";
import AlertsTable from "../components/AlertsTable";
import HBarChart from "../components/HBarChart";

const LIMIT = 200;

// detections written before the August enrichment carry no category
const categoryLabel = (c) => (c ? c.replace(/_/g, " ") : "no category");

export default function AiDetections() {
  const p = usePalette();
  const [data, setData] = useState(null);
  const [error, setError] = useState(null);

  const refresh = usePolling(async (isCurrent) => {
    try {
      const d = await getAiAlerts(LIMIT);
      if (!isCurrent()) return;
      setData(d);
      setError(null);
    } catch (e) {
      if (isCurrent()) setError(String(e.message ?? e));
    }
  }, 15000);

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
        title="Detections by category"
        description="Heuristic post-classification of the detections below. The model flags the deviation; the category makes it triageable."
        data={categories}
        seriesName="Detections"
        color={p.ai}
        empty={{
          icon: "visBarVertical",
          title: "No detections yet",
          body: "Generate traffic and give the consumer ~10 minutes to fill its window buffer.",
        }}
      />
      <EuiSpacer />
      <EuiPanel hasBorder>
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
          onRefresh={refresh}
        />
      </EuiPanel>
    </>
  );
}
