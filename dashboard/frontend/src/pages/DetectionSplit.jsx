import { useState } from "react";
import {
  EuiPanel,
  EuiText,
  EuiSpacer,
  EuiBadge,
  EuiFlexGroup,
  EuiFlexItem,
  EuiStat,
  EuiEmptyPrompt,
  EuiCallOut,
  useIsWithinBreakpoints,
} from "@elastic/eui";
import { getCombined } from "../api";
import { usePolling } from "../lib/usePolling";
import { scopeParams, scopeDeps } from "../lib/scope";
import { usePalette } from "../theme/ThemeProvider";
import { SeverityBadge } from "../components/badges";
import AlertFlyout from "../components/AlertFlyout";
import Dot from "../components/Dot";

const LIMIT = 300;
const fmtMinute = (ms) =>
  new Date(ms).toLocaleString([], { month: "short", day: "numeric", hour: "2-digit", minute: "2-digit" });

function meta(a) {
  if (a.source === "rule") return [a.agent, a.srcuser ?? a.dstuser, a.srcip].filter(Boolean).join(" · ");
  const size =
    a.pipeline === "web-streaming"
      ? `${a.request_count ?? "?"} requests`
      : `${a.event_count ?? "?"} events · ${a.distinct_users ?? "?"} users`;
  return `score ${a.score?.toFixed(3) ?? "—"} · ${size}`;
}

function Card({ alert, color, missed, missedColor, onOpen }) {
  return (
    <EuiPanel
      hasBorder
      paddingSize="s"
      onClick={() => onOpen(alert)}
      style={{ borderLeft: `3px solid ${color}`, margin: "4px 0" }}
    >
      <EuiFlexGroup gutterSize="s" alignItems="center" responsive={false} wrap>
        <EuiFlexItem grow={false}>
          <EuiText size="xs" color="subdued">
            <code>{alert.rule_id ?? "—"}</code>
          </EuiText>
        </EuiFlexItem>
        <EuiFlexItem grow={false}>
          <SeverityBadge level={alert.level} />
        </EuiFlexItem>
        {missed && (
          <EuiFlexItem grow={false}>
            <EuiBadge color={missedColor}>missed by rules</EuiBadge>
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

// The project's argument as one picture: rule alerts (level 10+) on the left,
// AI detections on the right, one row per minute. A minute with only a right
// side is one the signature ruleset stayed silent on.
export default function DetectionSplit({ scope }) {
  const p = usePalette();
  const narrow = useIsWithinBreakpoints(["xs", "s"]);
  const [alerts, setAlerts] = useState(null);
  const [error, setError] = useState(null);
  const [selected, setSelected] = useState(null);

  const refresh = usePolling(
    async (isCurrent) => {
      try {
        const c = await getCombined({ limit: LIMIT, ...scopeParams(scope) });
        if (!isCurrent()) return;
        setAlerts(c.alerts);
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
  const ruleCount = (alerts ?? []).filter((a) => a.source !== "ai").length;
  const aiCount = (alerts ?? []).length - ruleCount;
  const aiOnly = rows.filter(([, b]) => b.ai.length && !b.rule.length).length;
  const current = selected ? (alerts?.find((a) => a.id === selected.id) ?? selected) : null;
  const grid = { display: "grid", gridTemplateColumns: narrow ? "1fr" : "1fr 130px 1fr", columnGap: 12 };

  const stats = [
    { title: ruleCount, description: "Rule alerts (level 10+)", dot: p.rule },
    { title: aiCount, description: "AI detections", dot: p.ai },
    { title: aiOnly, description: "Minutes AI-only", dot: p.ai },
  ];

  return (
    <>
      {error && (
        <>
          <EuiCallOut title={`Alerts unavailable: ${error}`} color="danger" size="s" />
          <EuiSpacer />
        </>
      )}
      <EuiFlexGroup gutterSize="m" responsive={false} wrap>
        {stats.map((s) => (
          <EuiFlexItem key={s.description} grow={false} style={{ minWidth: 170 }}>
            <EuiPanel hasBorder paddingSize="s">
              <EuiStat
                title={alerts ? String(s.title) : "—"}
                titleSize="s"
                titleColor="default"
                description={
                  <>
                    <Dot color={s.dot} />
                    {s.description}
                  </>
                }
              />
            </EuiPanel>
          </EuiFlexItem>
        ))}
      </EuiFlexGroup>
      {alerts?.length >= LIMIT && (
        <EuiText size="xs" color="subdued">
          <p>Showing the latest {LIMIT} alerts in this range — narrow it to see earlier minutes.</p>
        </EuiText>
      )}
      <EuiSpacer />
      <EuiPanel hasBorder>
        {!narrow && (
          <div style={grid}>
            <EuiText size="xs" color="subdued" textAlign="right">
              <strong>Rule-based</strong> · Wazuh ruleset
            </EuiText>
            <EuiText size="xs" color="subdued" textAlign="center">
              minute
            </EuiText>
            <EuiText size="xs" color="subdued">
              <strong>Anomaly model</strong>
            </EuiText>
          </div>
        )}
        {alerts && rows.length === 0 && (
          <EuiEmptyPrompt
            iconType="timeline"
            titleSize="xs"
            title={<h3>No detections in this range</h3>}
            body={<p>Widen the time range, or generate traffic.</p>}
          />
        )}
        {rows.map(([minute, b]) => {
          const gap = b.ai.length > 0 && b.rule.length === 0;
          return (
            <div key={minute} style={{ ...grid, alignItems: "center", padding: "2px 0" }}>
              <div>
                {b.rule.map((a) => (
                  <Card key={a.id} alert={a} color={p.rule} onOpen={setSelected} />
                ))}
                {gap && !narrow && (
                  <EuiText size="xs" color="subdued" textAlign="right">
                    no rule fired
                  </EuiText>
                )}
              </div>
              <EuiText size="xs" color="subdued" textAlign={narrow ? "left" : "center"}>
                {fmtMinute(minute)}
              </EuiText>
              <div>
                {b.ai.map((a) => (
                  <Card
                    key={a.id}
                    alert={a}
                    color={p.ai}
                    missed={gap}
                    missedColor={p.ai}
                    onOpen={setSelected}
                  />
                ))}
              </div>
            </div>
          );
        })}
      </EuiPanel>
      <AlertFlyout alert={current} onClose={() => setSelected(null)} onRefresh={refresh} />
    </>
  );
}
