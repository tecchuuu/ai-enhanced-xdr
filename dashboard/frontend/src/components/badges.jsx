import { EuiBadge } from "@elastic/eui";
import { usePalette } from "../theme/ThemeProvider";

// source of a detection: Wazuh ruleset vs the AI pipeline.
// The label carries the identity; the color only reinforces it.
export function SourceBadge({ source }) {
  const p = usePalette();
  return source === "ai" ? (
    <EuiBadge color={p.ai}>AI model</EuiBadge>
  ) : (
    <EuiBadge color={p.rule}>rule</EuiBadge>
  );
}

// Wazuh severity convention: 12+ critical, 10+ high, 7+ medium, below = low
export function severityName(level) {
  if (level >= 12) return "critical";
  if (level >= 10) return "high";
  if (level >= 7) return "medium";
  return "low";
}

// Only the top two tiers are filled. Color earns attention by being rare — when
// every row is a saturated badge, none of them read as urgent.
export function SeverityBadge({ level }) {
  const p = usePalette();
  if (level == null) return <EuiBadge color="hollow">—</EuiBadge>;
  const name = severityName(level);
  const color =
    name === "critical" ? "danger" : name === "high" ? p.high : "hollow";
  return (
    <EuiBadge color={color}>
      {name} ({level})
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
