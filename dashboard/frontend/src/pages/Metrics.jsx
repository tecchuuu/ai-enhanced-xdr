import { useEffect, useState } from "react";
import {
  EuiSpacer,
  EuiPanel,
  EuiStat,
  EuiFlexGroup,
  EuiFlexItem,
  EuiButtonGroup,
  EuiText,
  EuiTitle,
  EuiCallOut,
} from "@elastic/eui";
import { getMetrics } from "../api";
import CategoryBreakdown from "../components/CategoryBreakdown";
import { usePalette } from "../theme/ThemeProvider";

const RANGES = [
  { id: "24", label: "24h" },
  { id: "168", label: "7d" },
  { id: "720", label: "30d" },
];

function Dot({ color }) {
  return (
    <span
      aria-hidden="true"
      style={{
        display: "inline-block",
        width: 8,
        height: 8,
        borderRadius: "50%",
        background: color,
        marginRight: 6,
        verticalAlign: "middle",
      }}
    />
  );
}

const fmtDuration = (secs) => {
  if (secs == null) return "—";
  if (secs < 90) return `${secs}s`;
  if (secs < 5400) return `${Math.round(secs / 60)}m`;
  return `${(secs / 3600).toFixed(1)}h`;
};

export default function Metrics() {
  const p = usePalette();
  const [rangeId, setRangeId] = useState("168");
  const [m, setM] = useState(null);
  const [error, setError] = useState(null);

  useEffect(() => {
    let alive = true;
    const load = () =>
      getMetrics(Number(rangeId))
        .then((d) => {
          if (!alive) return;
          setM(d);
          setError(null);
        })
        .catch((e) => {
          if (alive) setError(String(e.message ?? e));
        });
    load();
    const t = setInterval(load, 30000);
    return () => {
      alive = false;
      clearInterval(t);
    };
  }, [rangeId]);

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
      <EuiText size="s" color="subdued">
        <p>
          The live version of the rule-vs-AI comparison. <strong>Minutes AI-only</strong> is
          the headline: windows the anomaly model flagged while the signature ruleset stayed
          silent — the value the AI layer adds. False-positive rate and MTTR come from analyst
          triage on the AI detections.
        </p>
      </EuiText>
      <EuiSpacer size="s" />
      <EuiFlexGroup justifyContent="flexEnd" responsive={false}>
        <EuiFlexItem grow={false}>
          <EuiButtonGroup
            legend="Time range"
            options={RANGES}
            idSelected={rangeId}
            onChange={setRangeId}
            buttonSize="compressed"
          />
        </EuiFlexItem>
      </EuiFlexGroup>
      <EuiSpacer size="s" />

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

      <EuiSpacer />
      <EuiPanel hasBorder color="subdued">
        <EuiTitle size="xxs">
          <h3>How to read this</h3>
        </EuiTitle>
        <EuiSpacer size="s" />
        <EuiText size="s">
          <ul>
            <li>
              <strong>Rules-only vs rules+AI:</strong> rules caught {m?.rule_alerts ?? "—"};
              the AI added {o.ai_only ?? "—"} minute-windows on top that rules missed.
            </li>
            <li>
              <strong>Overlap ({o.both ?? "—"} min):</strong> both systems firing in the same
              minute — corroboration, not new coverage.
            </li>
            <li>
              <strong>{m?.triaged ?? 0} detections triaged</strong> — FP rate and MTTR are only
              meaningful once analysts have worked the queue.
            </li>
          </ul>
        </EuiText>
      </EuiPanel>

      <EuiSpacer />
      <CategoryBreakdown categories={m?.by_category} hours={RANGES.find((r) => r.id === rangeId)?.label} />
    </>
  );
}
