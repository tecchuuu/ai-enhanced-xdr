export const fmtTime = (ts) => (ts ? new Date(ts).toLocaleString() : "—");

// "45s ago", "12m ago", "3h ago", "2d ago"
export function fmtAgo(ts) {
  if (!ts) return "never";
  const s = Math.max(0, Math.round((Date.now() - Date.parse(ts)) / 1000));
  if (s < 90) return `${s}s ago`;
  if (s < 5400) return `${Math.round(s / 60)}m ago`;
  if (s < 172800) return `${Math.round(s / 3600)}h ago`;
  return `${Math.round(s / 86400)}d ago`;
}
