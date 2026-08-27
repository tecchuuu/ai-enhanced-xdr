import { EuiBadge } from "@elastic/eui";

// series colors, validated for the dark surface (dataviz six-checks)
export const COLOR_RULE = "#c17e15";
export const COLOR_AI = "#0ca58c";

// source of a detection: Wazuh ruleset vs the AI pipeline
export function SourceBadge({ source }) {
  return source === "ai" ? (
    <EuiBadge color={COLOR_AI}>AI model</EuiBadge>
  ) : (
    <EuiBadge color={COLOR_RULE}>rule</EuiBadge>
  );
}

// Wazuh severity convention: 12+ critical, 10+ high, 7+ medium, below = low
export function severityOf(level) {
  if (level >= 12) return { name: "critical", color: "danger" };
  if (level >= 10) return { name: "high", color: "#bd271e" };
  if (level >= 7) return { name: "medium", color: "warning" };
  return { name: "low", color: "hollow" };
}

export function SeverityBadge({ level }) {
  if (level == null) return <EuiBadge color="hollow">—</EuiBadge>;
  const s = severityOf(level);
  return (
    <EuiBadge color={s.color}>
      {s.name} ({level})
    </EuiBadge>
  );
}

// analyst workflow state — must match TRIAGE_STATES in the backend
export const TRIAGE_STATES = ["new", "investigating", "resolved", "false_positive"];

const TRIAGE_META = {
  new: { label: "new", color: "hollow" },
  investigating: { label: "investigating", color: "primary" },
  resolved: { label: "resolved", color: "success" },
  false_positive: { label: "false positive", color: "warning" },
};

export function TriageBadge({ status }) {
  const m = TRIAGE_META[status] ?? TRIAGE_META.new;
  return <EuiBadge color={m.color}>{m.label}</EuiBadge>;
}
