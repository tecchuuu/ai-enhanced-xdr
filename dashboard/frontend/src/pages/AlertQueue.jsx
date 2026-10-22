import { useState } from "react";
import {
  EuiPanel,
  EuiSpacer,
  EuiFlexGrid,
  EuiFlexItem,
  EuiCallOut,
  EuiText,
  EuiEmptyPrompt,
} from "@elastic/eui";
import { getQueue } from "../api";
import { usePolling } from "../lib/usePolling";
import { fmtAgo } from "../lib/format";
import { usePalette } from "../theme/ThemeProvider";
import AlertsTable from "../components/AlertsTable";
import { Tile } from "../components/StatPanels";

// The analyst's starting point: what is still open (new or being
// investigated), most severe first and, within a severity, longest-waiting
// first — the order a SOC works a queue in. Deliberately not tied to the time
// picker (GET /api/queue covers the last 7 days): an open critical alert must
// not vanish because the range is "last 24 hours". Reviewing an alert as
// resolved or false positive takes it off the list.
export default function AlertQueue({ scope }) {
  const p = usePalette();
  const [q, setQ] = useState(null);
  const [error, setError] = useState(null);

  usePolling(
    async (isCurrent) => {
      try {
        const d = await getQueue({});
        if (!isCurrent()) return;
        setQ(d);
        setError(null);
      } catch (e) {
        if (isCurrent()) setError(String(e.message ?? e));
      }
    },
    15000,
    [scope.refreshKey]
  );

  const sev = q?.severity ?? {};
  const tiles = [
    { value: q && sev.critical, label: "Critical, open", dot: p.critical },
    { value: q && sev.high, label: "High, open", dot: p.high },
    {
      value: q && q.investigating,
      label: "Being investigated",
      note: "someone set them to investigating",
    },
    {
      value: q ? (q.oldest_new ? fmtAgo(q.oldest_new).replace(" ago", "") : "—") : null,
      label: "Oldest unreviewed",
      note: q?.oldest_new ? "how long the oldest new alert has waited" : "nothing waiting",
      info: "How long the oldest alert nobody has looked at yet has been waiting. In a SOC this is the number that says whether the queue is under control.",
    },
  ];

  return (
    <>
      {error && (
        <>
          <EuiCallOut title={`Queue unavailable: ${error}`} color="danger" size="s" />
          <EuiSpacer />
        </>
      )}
      <EuiFlexGrid columns={4} gutterSize="m">
        {tiles.map((t) => (
          <EuiFlexItem key={t.label}>
            <Tile {...t} size="m" />
          </EuiFlexItem>
        ))}
      </EuiFlexGrid>
      <EuiSpacer />
      <EuiPanel hasBorder>
        <EuiText size="s" color="subdued">
          <p>
            {q ? `${q.count.toLocaleString()} open` : "Loading"} — Wazuh alerts at level 10 and above
            and every AI detection from the last {q?.days ?? 7} days that nobody has resolved or
            marked as a false positive. Most severe first; within a severity, the longest-waiting
            first. Open one to review it.
          </p>
        </EuiText>
        {q?.truncated && (
          <EuiText size="xs" color="subdued">
            <p>More than 1,000 open alerts of one kind — the most severe and oldest are shown.</p>
          </EuiText>
        )}
        <EuiSpacer size="s" />
        {q && q.alerts.length === 0 ? (
          <EuiEmptyPrompt
            iconType="checkCircle"
            titleSize="xs"
            title={<h3>Nothing open</h3>}
            body={<p>Every alert from the last {q.days} days has been reviewed.</p>}
          />
        ) : (
          <AlertsTable
            alerts={q?.alerts ?? []}
            loading={q == null && !error}
            showWaiting
            showTriageFilter={false}
            initialSort={null}
          />
        )}
      </EuiPanel>
    </>
  );
}
