import { EuiBadge } from "@elastic/eui";
import { usePalette } from "../theme/ThemeProvider";
import Dot from "./Dot";

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

// Only critical is filled. Color earns attention by being rare — when every row
// is a saturated badge, none of them read as urgent. High is a quiet badge with
// a red dot: two filled reds (EUI danger and palette.high) were too close to
// tell apart, so the tiers now differ in fill, not just in shade.
export function SeverityBadge({ level }) {
  const p = usePalette();
  if (level == null) return <EuiBadge color="hollow">—</EuiBadge>;
  const name = severityName(level);
  if (name === "critical") return <EuiBadge color="danger">critical ({level})</EuiBadge>;
  return (
    <EuiBadge color="hollow">
      {name === "high" && <Dot color={p.high} />}
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
