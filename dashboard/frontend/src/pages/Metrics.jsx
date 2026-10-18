import { useState } from "react";
import {
  EuiSpacer,
  EuiPanel,
  EuiStat,
  EuiFlexGroup,
  EuiFlexItem,
  EuiText,
  EuiCallOut,
  EuiAccordion,
} from "@elastic/eui";
import { getMetrics } from "../api";
import { usePolling } from "../lib/usePolling";
import { scopeParams, scopeDeps } from "../lib/scope";
import { usePalette } from "../theme/ThemeProvider";
import Dot from "../components/Dot";

const fmtDuration = (secs) => {
  if (secs == null) return "—";
  if (secs < 90) return `${secs}s`;
  if (secs < 5400) return `${Math.round(secs / 60)}m`;
  return `${(secs / 3600).toFixed(1)}h`;
};

export default function Metrics({ scope }) {
  const p = usePalette();
  const [m, setM] = useState(null);
  const [error, setError] = useState(null);

  usePolling(
    async (isCurrent) => {
      try {
        const d = await getMetrics(scopeParams(scope));
        if (!isCurrent()) return;
        setM(d);
        setError(null);
      } catch (e) {
        if (isCurrent()) setError(String(e.message ?? e));
      }
    },
    30000,
    scopeDeps(scope)
  );

  const o = m?.overlap_minutes ?? {};

  const tiles = [
    { title: m?.rule_alerts ?? "—", description: "Rule alerts (level 10+)", dot: p.rule },
    { title: m?.ai_detections ?? "—", description: "AI detections", dot: p.ai },
    { title: o.ai_only ?? "—", description: "Minutes AI-only (rules silent)", dot: p.ai },
    { title: o.both ?? "—", description: "Minutes both fired", dot: null },
    {
      title: m ? `${(m.false_positive_rate * 100).toFixed(1)}%` : "—",
      description: `AI false-positive rate (${m?.false_positives ?? 0} flagged)`,
      dot: null,
    },
    { title: fmtDuration(m?.mttr_seconds), description: "Mean time to resolve", dot: null },
  ];

  return (
    <>

      {error && (
        <>
          <EuiCallOut title={`Metrics unavailable: ${error}`} color="warning" size="s" />
          <EuiSpacer />
        </>
      )}

      <EuiFlexGroup wrap>
        {tiles.map((t) => (
          <EuiFlexItem key={t.description} style={{ minWidth: 180 }}>
            <EuiPanel hasBorder>
              <EuiStat
                title={String(t.title)}
                description={
                  <>
                    {t.dot && <Dot color={t.dot} />}
                    {t.description}
                  </>
                }
                titleColor="default"
                titleSize="l"
              />
            </EuiPanel>
          </EuiFlexItem>
        ))}
      </EuiFlexGroup>

      {m?.ai_by_model?.length > 0 && (
        <>
          <EuiSpacer size="s" />
          <EuiText size="s" color="subdued">
            <p>
              AI detections by model:{" "}
              {m.ai_by_model.map((x) => `${x.model} ${x.count}`).join(" · ")}
            </p>
          </EuiText>
        </>
      )}

      <EuiSpacer />
      <EuiPanel hasBorder color="subdued" paddingSize="s">
        <EuiAccordion id="metrics-how-to-read" buttonContent="How to read this" paddingSize="s">
          <EuiText size="s">
            <ul>
              <li>
                <strong>Minutes AI-only</strong> is the headline: minutes the anomaly model
                flagged while the signature ruleset stayed silent — the value the AI layer adds.
              </li>
              <li>
                <strong>Rules-only vs rules+AI:</strong> rules caught {m?.rule_alerts ?? "—"};
                the AI added {o.ai_only ?? "—"} minute-windows on top that rules missed.
              </li>
              <li>
                <strong>Overlap ({o.both ?? "—"} min):</strong> both systems firing in the same
                minute — corroboration, not new coverage.
              </li>
              <li>
                <strong>{m?.triaged ?? 0} alerts triaged</strong> in this range — FP rate and
                MTTR come from analyst triage on the AI detections, so they only mean something
                once the queue has been worked.
              </li>
            </ul>
          </EuiText>
        </EuiAccordion>
      </EuiPanel>
    </>
  );
}
