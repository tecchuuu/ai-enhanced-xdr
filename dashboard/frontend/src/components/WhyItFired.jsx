import { EuiPanel, EuiTitle, EuiText, EuiSpacer, EuiBasicTable, EuiBadge } from "@elastic/eui";
import PanelTitle from "./PanelTitle";
import { displayScore } from "../lib/format";

const LABELS = {
  event_count: "Login events",
  distinct_users: "Distinct users",
  max_level: "Highest Wazuh level",
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
// past the cutoff reads as clear
const CLEAR_MARGIN = 0.1;

const num = (v) => (v == null ? "—" : Number.isInteger(v) ? String(v) : String(+v.toFixed(3)));
// scores to two places everywhere (tables, the assistant), so they match
const sc = (v) => (v == null ? "—" : v.toFixed(2));
const times = (r) => (r >= 10 ? `${Math.round(r)}×` : `${r.toFixed(1)}×`);

// The evidence the detector recorded when it flagged this minute: its values
// next to what the un-flagged minutes in the same fit looked like, and the
// score cutoff that fit used. Scores are shown flipped (higher = more unusual,
// see displayScore). Text, not a gauge — each model scores on its own scale,
// so a fixed bar would imply a comparability that isn't there.
export default function WhyItFired({ alert }) {
  const { features, baseline, windows_scored: scored } = alert;
  const score = displayScore(alert.score);
  const cutoff = displayScore(alert.threshold);

  if (!features || !baseline) {
    return (
      <EuiPanel hasBorder>
        <EuiTitle size="xxs">
          <h3>Why it fired</h3>
        </EuiTitle>
        <EuiText size="s" color="subdued">
          <p>
            Anomaly score {sc(score)}. This detection was saved before the detectors started
            recording what normal looked like, so only the score is available.
          </p>
        </EuiText>
      </EuiPanel>
    );
  }

  const margin = cutoff != null && score != null ? score - cutoff : null;
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
    { field: "label", name: "Measure" },
    { field: "value", name: "This minute", render: num, width: "100px" },
    { field: "median", name: "Typical", render: num, width: "90px" },
    { field: "p95", name: "Usually below", render: num, width: "110px" },
    {
      name: "",
      width: "120px",
      render: (r) =>
        r.above ? (
          <EuiBadge color="warning">{r.ratio ? `${times(r.ratio)} typical` : "unusually high"}</EuiBadge>
        ) : null,
    },
  ];

  return (
    <EuiPanel hasBorder>
      <PanelTitle
        title="Why it fired"
        size="xxs"
        as="h3"
        info={`"Typical" and "usually below" come from the recent minutes this model did not flag (${scored} minutes when this one was scored): the middle value, and the value 95% of them stayed under. The model flags a fixed share of the most unusual minutes, so its cutoff moves with recent activity.`}
      />
      <EuiSpacer size="xs" />
      <EuiText size="s">
        <p>
          Anomaly score <strong>{sc(score)}</strong>
          {margin != null && (
            <>
              , flagged because it is above this model&rsquo;s cutoff of {sc(cutoff)}{" "}
              <EuiBadge color={margin > CLEAR_MARGIN ? "danger" : "hollow"}>
                {margin > CLEAR_MARGIN ? "clearly above" : "just above"}
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
