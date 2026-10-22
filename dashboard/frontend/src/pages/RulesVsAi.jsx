import { useState } from "react";
import {
  EuiPanel,
  EuiText,
  EuiSpacer,
  EuiBadge,
  EuiFlexGroup,
  EuiFlexGrid,
  EuiFlexItem,
  EuiEmptyPrompt,
  EuiCallOut,
  EuiAccordion,
  useIsWithinBreakpoints,
} from "@elastic/eui";
import { getCombined, getMetrics } from "../api";
import { usePolling } from "../lib/usePolling";
import { scopeParams, scopeDeps } from "../lib/scope";
import { usePalette } from "../theme/ThemeProvider";
import { useNav } from "../lib/nav";
import { fmtScore, modelLabel } from "../lib/format";
import { SeverityBadge } from "../components/badges";
import { Tile, ONLY_AI_INFO } from "../components/StatPanels";

const LIMIT = 300;
const fmtMinute = (ms) =>
  new Date(ms).toLocaleString([], { month: "short", day: "numeric", hour: "2-digit", minute: "2-digit", hour12: false });

const fmtDuration = (secs) => {
  if (secs == null) return null;
  if (secs < 90) return `${secs}s`;
  if (secs < 5400) return `${Math.round(secs / 60)}m`;
  return `${(secs / 3600).toFixed(1)}h`;
};

function meta(a) {
  if (a.source === "rule") return [a.agent, a.srcuser ?? a.dstuser, a.srcip].filter(Boolean).join(" · ");
  const size =
    a.pipeline === "web-streaming"
      ? `${a.request_count ?? "?"} requests`
      : `${a.event_count ?? "?"} events · ${a.distinct_users ?? "?"} users`;
  return `${modelLabel(a.model)} · score ${fmtScore(a.score)} · ${size}`;
}

function Card({ alert, color, onlyAi, onOpen }) {
  return (
    <EuiPanel
      hasBorder
      paddingSize="s"
      onClick={() => onOpen(alert)}
      style={{ borderLeft: `3px solid ${color}`, margin: "4px 0" }}
    >
      <EuiFlexGroup gutterSize="s" alignItems="center" responsive={false} wrap>
        {/* a Wazuh rule number means something to a Wazuh user; the AI's doesn't */}
        {alert.source === "rule" && alert.rule_id && (
          <EuiFlexItem grow={false}>
            <EuiText size="xs" color="subdued">
              <code>rule {alert.rule_id}</code>
            </EuiText>
          </EuiFlexItem>
        )}
        <EuiFlexItem grow={false}>
          <SeverityBadge level={alert.level} />
        </EuiFlexItem>
        {onlyAi && (
          <EuiFlexItem grow={false}>
            <EuiBadge color="hollow">flagged only by AI</EuiBadge>
          </EuiFlexItem>
        )}
      </EuiFlexGroup>
      <EuiText size="s">
        <p style={{ margin: "4px 0 0" }}>{alert.description}</p>
      </EuiText>
      <EuiText size="xs" color="subdued">
        <p style={{ margin: 0 }}>{meta(alert)}</p>
      </EuiText>
    </EuiPanel>
  );
}

// The project's argument on one page: what the Wazuh rules raised and what the
// AI raised, side by side, minute by minute — with the counts and the analyst
// verdicts on top. The tiles come from /api/metrics (the whole range); the
// timeline from the combined feed (the latest LIMIT alerts).
export default function RulesVsAi({ scope }) {
  const p = usePalette();
  const { openAlert } = useNav();
  const narrow = useIsWithinBreakpoints(["xs", "s"]);
  const [alerts, setAlerts] = useState(null);
  const [m, setM] = useState(null);
  const [error, setError] = useState(null);

  usePolling(
    async (isCurrent) => {
      try {
        const s = scopeParams(scope);
        const [c, mm] = await Promise.all([getCombined({ limit: LIMIT, ...s }), getMetrics(s)]);
        if (!isCurrent()) return;
        setAlerts(c.alerts);
        setM(mm);
        setError(null);
      } catch (e) {
        if (isCurrent()) setError(String(e.message ?? e));
      }
    },
    30000,
    scopeDeps(scope)
  );

  const minutes = new Map();
  for (const a of alerts ?? []) {
    const t = Date.parse(a.timestamp);
    if (Number.isNaN(t)) continue;
    const key = Math.floor(t / 60000) * 60000;
    if (!minutes.has(key)) minutes.set(key, { rule: [], ai: [] });
    minutes.get(key)[a.source === "ai" ? "ai" : "rule"].push(a);
  }
  const rows = [...minutes.entries()].sort((a, b) => b[0] - a[0]);
  const grid = { display: "grid", gridTemplateColumns: narrow ? "1fr" : "1fr 120px 1fr", columnGap: 12 };

  const reviewed = m?.ai_reviewed ?? 0;
  const fpValue = m ? (reviewed ? `${m.false_positives} of ${reviewed}` : "—") : null;
  const fpNote = m
    ? reviewed
      ? `${Math.round(m.false_positive_rate * 100)}% of the reviewed AI detections`
      : "no AI detections reviewed yet"
    : null;

  const tiles = [
    { value: m?.rule_alerts, label: "Wazuh alerts (level 10+)", dot: p.rule },
    { value: m?.ai_detections, label: "AI detections", dot: p.ai },
    {
      value: m?.ai_with_rule_detections,
      label: "Flagged by both",
      note: "AI detections with a Wazuh alert in the same minute",
    },
    {
      value: m?.ai_only_detections,
      label: "Flagged only by AI",
      dot: p.ai,
      note: "no Wazuh alert in the same minute",
      info: ONLY_AI_INFO,
    },
    {
      value: fpValue,
      label: "False positives",
      note: fpNote,
      info: "From analyst review: on an AI detection's Triage tab, 'false positive' means it was wrong, 'resolved' that it was real. Only reviewed detections count, so this fills in as the queue is worked.",
    },
    {
      value: m ? (fmtDuration(m.mttr_seconds) ?? "—") : null,
      label: "Average time to resolve",
      note: m?.mttr_seconds == null ? "no alerts closed yet" : "from the alert to its verdict",
    },
  ];

  return (
    <>
      {error && (
        <>
          <EuiCallOut title={`Alerts unavailable: ${error}`} color="danger" size="s" />
          <EuiSpacer />
        </>
      )}
      {/* two even rows: the counts, then what the analysts' reviews say */}
      <EuiFlexGrid columns={3} gutterSize="m">
        {tiles.map((t) => (
          <EuiFlexItem key={t.label}>
            <Tile {...t} size="s" />
          </EuiFlexItem>
        ))}
      </EuiFlexGrid>
      <EuiSpacer size="s" />
      <EuiPanel hasBorder color="subdued" paddingSize="s">
        <EuiAccordion id="rules-vs-ai-how-to-read" buttonContent="How to read this page" paddingSize="s">
          <EuiText size="s">
            <ul>
              <li>
                Each row below is one minute. Left: alerts from Wazuh&rsquo;s rules (level 10 and
                above). Right: what the AI models flagged in the same minute.
              </li>
              <li>
                <strong>Flagged only by AI</strong> means the AI flagged a minute in which no Wazuh
                rule fired. That is a disagreement to review, not proof of a missed attack — the
                AI can be wrong too.
              </li>
              <li>
                Whether a detection was right is only known once someone reviews it. The{" "}
                <strong>False positives</strong> tile counts those reviews. How accurate the models
                are overall was measured separately, in the evaluation, where the real attacks are
                known in advance.
              </li>
            </ul>
          </EuiText>
        </EuiAccordion>
      </EuiPanel>
      {alerts?.length >= LIMIT && (
        <EuiText size="xs" color="subdued">
          <p>Showing the latest {LIMIT} alerts in this range — narrow it to see earlier minutes.</p>
        </EuiText>
      )}
      <EuiSpacer />
      <EuiPanel hasBorder>
        {!narrow && (
          <div style={grid}>
            <EuiText size="s" textAlign="right">
              <strong>Wazuh rules</strong>
            </EuiText>
            <EuiText size="s" textAlign="center" color="subdued">
              Time
            </EuiText>
            <EuiText size="s">
              <strong>AI models</strong>
            </EuiText>
          </div>
        )}
        {alerts && rows.length === 0 && (
          <EuiEmptyPrompt
            iconType="timeline"
            titleSize="xs"
            title={<h3>No alerts in this range</h3>}
            body={<p>Widen the time range, or generate traffic.</p>}
          />
        )}
        {rows.map(([minute, b]) => {
          const onlyAi = b.ai.length > 0 && b.rule.length === 0;
          return (
            <div key={minute} style={{ ...grid, alignItems: "center", padding: "2px 0" }}>
              <div>
                {b.rule.map((a) => (
                  <Card key={a.id} alert={a} color={p.rule} onOpen={openAlert} />
                ))}
                {onlyAi && !narrow && (
                  <EuiText size="xs" color="subdued" textAlign="right">
                    no Wazuh alert
                  </EuiText>
                )}
              </div>
              <EuiText size="xs" color="subdued" textAlign={narrow ? "left" : "center"}>
                {fmtMinute(minute)}
              </EuiText>
              <div>
                {b.ai.map((a) => (
                  <Card key={a.id} alert={a} color={p.ai} onlyAi={onlyAi} onOpen={openAlert} />
                ))}
              </div>
            </div>
          );
        })}
      </EuiPanel>
    </>
  );
}
