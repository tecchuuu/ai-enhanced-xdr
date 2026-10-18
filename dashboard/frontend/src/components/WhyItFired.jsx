import { EuiPanel, EuiTitle, EuiText, EuiSpacer, EuiBasicTable, EuiBadge } from "@elastic/eui";
import PanelTitle from "./PanelTitle";

const LABELS = {
  event_count: "Events in window",
  distinct_users: "Distinct users",
  max_level: "Highest rule level",
  events_per_user: "Events per user",
  request_count: "Requests",
  distinct_urls: "Distinct URLs",
  error_ratio: "Error ratio",
  not_found_count: "404 responses",
  post_ratio: "POST ratio",
  requests_per_ip: "Requests per IP",
  hour: "Hour (UTC)",
};

// same verdict line as the explainer (explainer._score_line): more than 0.1
// past the cutoff reads as strong
const STRONG_MARGIN = 0.1;

const num = (v) => (v == null ? "—" : Number.isInteger(v) ? String(v) : String(+v.toFixed(3)));
const times = (r) => (r >= 10 ? `${Math.round(r)}×` : `${r.toFixed(1)}×`);

// The evidence the detector recorded when it flagged this window: its feature
// values next to what the un-flagged windows in the same fit looked like, and
// the score cutoff that fit used. Text, not a gauge — each model scores on its
// own scale, so a fixed bar would imply a comparability that isn't there.
export default function WhyItFired({ alert }) {
  const { score, threshold, features, baseline, windows_scored: scored } = alert;

  if (!features || !baseline) {
    return (
      <EuiPanel hasBorder>
        <EuiTitle size="xxs">
          <h3>Why it fired</h3>
        </EuiTitle>
        <EuiText size="s" color="subdued">
          <p>
            Anomaly score {num(score)}. This detection was written before the consumers
            recorded their evidence (baseline and cutoff), so only the score is available.
          </p>
        </EuiText>
      </EuiPanel>
    );
  }

  const margin = threshold != null && score != null ? threshold - score : null;
  const rows = Object.entries(features).map(([name, value]) => {
    const b = baseline[name];
    // hour is a clock reading, not a quantity — no "above normal" for it
    const comparable = name !== "hour" && b;
    return {
      name,
      label: LABELS[name] ?? name.replace(/_/g, " "),
      value,
      median: b?.median,
      p95: b?.p95,
      above: comparable && value > b.p95,
      ratio: comparable && b.median > 0 ? value / b.median : null,
    };
  });

  const columns = [
    { field: "label", name: "Feature" },
    { field: "value", name: "This window", render: num, width: "100px" },
    { field: "median", name: "Normal median", render: num, width: "110px" },
    { field: "p95", name: "Normal p95", render: num, width: "100px" },
    {
      name: "",
      width: "120px",
      render: (r) =>
        r.above ? (
          <EuiBadge color="warning">{r.ratio ? `${times(r.ratio)} median` : "above p95"}</EuiBadge>
        ) : null,
    },
  ];

  return (
    <EuiPanel hasBorder>
      <PanelTitle
        title="Why it fired"
        size="xxs"
        as="h3"
        info={`"Normal" is the windows in the model's rolling buffer that it did not flag when this one was scored (${scored} windows in that fit). The cutoff moves with the buffer: the model flags a fixed share of windows, not a fixed score. Lower scores are more anomalous.`}
      />
      <EuiSpacer size="xs" />
      <EuiText size="s">
        <p>
          Score <strong>{num(score)}</strong>
          {margin != null && (
            <>
              {" "}against a cutoff of {num(threshold)}: {num(margin)} past it{" "}
              <EuiBadge color={margin > STRONG_MARGIN ? "danger" : "hollow"}>
                {margin > STRONG_MARGIN ? "strong" : "borderline"}
              </EuiBadge>
            </>
          )}
        </p>
      </EuiText>
      <EuiSpacer size="s" />
      <EuiBasicTable items={rows} columns={columns} compressed tableLayout="auto" />
    </EuiPanel>
  );
}
