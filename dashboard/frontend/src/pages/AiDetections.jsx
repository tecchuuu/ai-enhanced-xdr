import { useState } from "react";
import { EuiPanel, EuiSpacer, EuiCallOut, EuiFlexGroup, EuiFlexItem, EuiText } from "@elastic/eui";
import { getAiAlerts, getBreakdown } from "../api";
import { usePolling } from "../lib/usePolling";
import { usePagedFeed } from "../lib/usePagedFeed";
import { scopeParams, scopeDeps } from "../lib/scope";
import { usePalette } from "../theme/ThemeProvider";
import AlertsTable from "../components/AlertsTable";
import HBarChart from "../components/HBarChart";
import FeedSearch from "../components/FeedSearch";

// Same layout as the Wazuh alerts page: chart, filters, table — both covering
// every detection matching the search in this range, not just one page.
export default function AiDetections({ scope }) {
  const p = usePalette();
  const [q, setQ] = useState("");
  const [types, setTypes] = useState(null);
  const { data, error, server } = usePagedFeed(getAiAlerts, { q }, scope);

  usePolling(
    async (isCurrent) => {
      try {
        const b = await getBreakdown({ source: "ai", q, ...scopeParams(scope) });
        if (isCurrent()) setTypes(b.items);
      } catch {
        /* the table reports API problems */
      }
    },
    30000,
    [q, ...scopeDeps(scope)]
  );

  return (
    <>
      <HBarChart
        title="Detections by attack type"
        info="The likely attack type of every detection matching the search in this range, assigned by simple rules after the model has flagged the minute. The model finds the unusual activity; the type helps decide what to do about it."
        data={types}
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
            <FeedSearch placeholder="Search IP, URL, attack type or text, then Enter" onSearch={setQ} />
          </EuiFlexItem>
          {data && (
            <EuiFlexItem grow={false}>
              <EuiText size="xs" color="subdued">
                {data.count.toLocaleString()} detection{data.count === 1 ? "" : "s"}
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
          alerts={data?.alerts ?? []}
          loading={data == null && !error}
          showScore
          showSource={false}
          server={server}
        />
      </EuiPanel>
    </>
  );
}
