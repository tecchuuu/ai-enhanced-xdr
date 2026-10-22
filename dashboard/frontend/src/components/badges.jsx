import { EuiBadge } from "@elastic/eui";
import { usePalette } from "../theme/ThemeProvider";

// source of a detection: Wazuh ruleset vs the AI pipeline.
// The label carries the identity; the color only reinforces it.
export function SourceBadge({ source }) {
  const p = usePalette();
  return source === "ai" ? (
    <EuiBadge color={p.ai}>AI</EuiBadge>
  ) : (
    <EuiBadge color={p.rule}>Wazuh</EuiBadge>
  );
}

// Wazuh's own severity bands (the dashboard's "Last 24 hours alerts" panel):
// 15+ critical, 12-14 high, 7-11 medium, 0-6 low. Using the same bands means an
// alert has the same severity name here as in the Wazuh dashboard. The AI
// detectors write levels 7/10/12, so an anomaly is at most "high" — Wazuh keeps
// "critical" for alerts that cannot be false positives.
export function severityName(level) {
  if (level >= 15) return "critical";
  if (level >= 12) return "high";
  if (level >= 7) return "medium";
  return "low";
}

const SEVERITY_LABEL = { critical: "Critical", high: "High", medium: "Medium", low: "Low" };

// The usual SOC color ramp, with the label and the Wazuh level in the text so
// it reads without color too.
export function SeverityBadge({ level }) {
  const p = usePalette();
  if (level == null) return <EuiBadge color="hollow">—</EuiBadge>;
  const name = severityName(level);
  return (
    <EuiBadge color={p[name]}>
      {SEVERITY_LABEL[name]} ({level})
    </EuiBadge>
  );
}

// analyst workflow state — must match TRIAGE_STATES in the backend.
// Kept off the severity colors: a "false positive" must not look like a severity.
export const TRIAGE_STATES = ["new", "investigating", "resolved", "false_positive"];

const TRIAGE_META = {
  new: { label: "new", color: "hollow" },
  investigating: { label: "investigating", color: "primary" },
  resolved: { label: "resolved", color: "success" },
  false_positive: { label: "false positive", color: "default" },
};

export function TriageBadge({ status }) {
  const m = TRIAGE_META[status] ?? TRIAGE_META.new;
  return <EuiBadge color={m.color}>{m.label}</EuiBadge>;
}
