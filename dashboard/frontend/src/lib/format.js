// "Oct 22, 15:11:05" — 24-hour and short enough for one table line; the year
// only appears when it isn't this year.
export function fmtTime(ts) {
  if (!ts) return "—";
  const d = new Date(ts);
  if (Number.isNaN(d.getTime())) return "—";
  return d.toLocaleString([], {
    ...(d.getFullYear() !== new Date().getFullYear() && { year: "numeric" }),
    month: "short",
    day: "numeric",
    hour: "2-digit",
    minute: "2-digit",
    second: "2-digit",
    hour12: false,
  });
}

// "45s ago", "12m ago", "3h ago", "2d ago"
export function fmtAgo(ts) {
  if (!ts) return "never";
  const s = Math.max(0, Math.round((Date.now() - Date.parse(ts)) / 1000));
  if (s < 90) return `${s}s ago`;
  if (s < 5400) return `${Math.round(s / 60)}m ago`;
  if (s < 172800) return `${Math.round(s / 3600)}h ago`;
  return `${Math.round(s / 86400)}d ago`;
}

// The detectors store scores the scikit-learn way round (lower = more
// anomalous). Shown flipped, so higher = more unusual, as analysts expect.
// Each model keeps its own scale (Isolation Forest 0-1, the autoencoders in
// standard deviations), so scores are comparable within a model, not across.
export const displayScore = (s) => (s == null ? null : -s);

export function fmtScore(s) {
  const v = displayScore(s);
  return v == null ? "—" : v.toFixed(2);
}

// the model names as the detectors write them, in one readable form
export function modelLabel(m) {
  if (!m) return "—";
  if (/isolation/i.test(m)) return "Isolation Forest";
  if (/dfencoder|dfp|morpheus/i.test(m)) return "Morpheus DFP";
  if (/autoencoder/i.test(m)) return "Autoencoder";
  return m;
}

// stored response references read "100001 — AI: anomalous …"; the rule id
// means nothing to a reader, the description does
export const refText = (ref) => (ref ? ref.replace(/^\S+ — /, "") : "—");
