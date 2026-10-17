import { useEffect, useState } from "react";
import { EuiPanel, EuiTitle, EuiText, EuiSpacer, EuiInMemoryTable, EuiCallOut } from "@elastic/eui";
import { getRelated } from "../api";
import { fmtTime } from "../lib/format";
import { SeverityBadge } from "./badges";

const columns = [
  { field: "timestamp", name: "Time", render: fmtTime, width: "170px" },
  { field: "level", name: "Severity", render: (l) => <SeverityBadge level={l} />, width: "120px" },
  { field: "rule_id", name: "Rule", width: "70px" },
  { field: "description", name: "Description", truncateText: true },
  { name: "User", render: (e) => e.srcuser ?? e.dstuser ?? "—", width: "100px" },
];

function summary(d, isAi) {
  if (!d.basis) return "This alert has no source IP or agent, so there is nothing to correlate.";
  const who = d.basis === "srcip" ? `from ${d.ips.join(", ")}` : `on agent ${d.agent} (the alert carries no source IP)`;
  const shown = d.count > d.events.length ? ` Showing the first ${d.events.length}.` : "";
  return (
    `${d.count} rule alert${d.count === 1 ? "" : "s"} at any level ${who}, ` +
    `${fmtTime(d.start)} – ${fmtTime(d.end)}` +
    (isAi ? " — the decoded events behind this window." : ".") +
    shown
  );
}

// Rule alerts around one alert (5 min either side), from the same source IPs.
// For an AI detection that's what the model aggregated, as far as the ruleset
// decoded it; for a rule alert, what else the source did around it.
export default function RelatedEvents({ alert }) {
  const [data, setData] = useState(null);
  const [error, setError] = useState(null);

  useEffect(() => {
    let alive = true;
    setData(null);
    setError(null);
    getRelated(alert.id)
      .then((d) => alive && setData(d))
      .catch((e) => alive && setError(String(e.message ?? e)));
    return () => {
      alive = false;
    };
  }, [alert.id]);

  return (
    <EuiPanel hasBorder>
      <EuiTitle size="xxs">
        <h3>Related events</h3>
      </EuiTitle>
      <EuiText size="xs" color="subdued">
        <p>{data ? summary(data, alert.source === "ai") : error ? "" : "Loading…"}</p>
      </EuiText>
      {error && <EuiCallOut title={error} color="danger" iconType="warning" size="s" />}
      {data?.events.length > 0 && (
        <>
          <EuiSpacer size="s" />
          <EuiInMemoryTable
            items={data.events}
            columns={columns}
            pagination={{ initialPageSize: 10, showPerPageOptions: false }}
            sorting={{ sort: { field: "timestamp", direction: "asc" } }}
            compressed
          />
        </>
      )}
    </EuiPanel>
  );
}
