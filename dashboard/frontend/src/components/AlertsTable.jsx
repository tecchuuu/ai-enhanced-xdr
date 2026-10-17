import { useState } from "react";
import { EuiInMemoryTable, EuiFilterGroup, EuiFilterButton, EuiLink, EuiSpacer } from "@elastic/eui";
import { SourceBadge, SeverityBadge, TriageBadge, TRIAGE_STATES } from "./badges";
import AlertFlyout from "./AlertFlyout";
import { fmtTime } from "../lib/format";
import { useOpenIp } from "../lib/ipContext";

// showSource: off on single-source pages, where every row would say the same thing.
// Searching is the page's job (server-side, see FeedSearch); the table only
// filters what it was given by triage state.
export default function AlertsTable({
  alerts = [],
  loading,
  showScore = false,
  showSource = true,
  showTriageFilter = true,
  onRefresh,
}) {
  const openIp = useOpenIp();
  const [selected, setSelected] = useState(null);
  const [triageShown, setTriageShown] = useState([]); // empty = every state

  // keep the open flyout pointed at the freshest copy of its alert, so a triage
  // save (which refetches upstream) is reflected without reopening
  const current = selected ? (alerts.find((a) => a.id === selected.id) ?? selected) : null;

  const counts = {};
  for (const a of alerts) counts[a.triage_status ?? "new"] = (counts[a.triage_status ?? "new"] ?? 0) + 1;
  const items = triageShown.length
    ? alerts.filter((a) => triageShown.includes(a.triage_status ?? "new"))
    : alerts;
  const toggle = (s) =>
    setTriageShown((t) => (t.includes(s) ? t.filter((x) => x !== s) : [...t, s]));

  const columns = [
    {
      field: "timestamp",
      name: "Time",
      render: fmtTime,
      sortable: true,
      width: "170px",
    },
    { field: "agent", name: "Agent", sortable: true, width: "120px" },
    { field: "rule_id", name: "Rule ID", sortable: true, width: "90px" },
    {
      field: "level",
      name: "Severity",
      render: (level) => <SeverityBadge level={level} />,
      sortable: true,
      width: "120px",
    },
    { field: "description", name: "Description", truncateText: true },
    {
      field: "category",
      name: "Category",
      sortable: true,
      width: "150px",
      render: (c) => c ?? "—",
    },
    showSource && {
      field: "source",
      name: "Source",
      render: (source) => <SourceBadge source={source} />,
      sortable: true,
      width: "100px",
    },
    {
      field: "triage_status",
      name: "Triage",
      render: (s) => <TriageBadge status={s} />,
      sortable: true,
      width: "120px",
    },
    {
      field: "srcip",
      name: "Source IP",
      sortable: true,
      width: "130px",
      // the IP pivot, without also opening the row's alert flyout
      render: (ip) =>
        ip ? (
          <EuiLink
            onClick={(e) => {
              e.stopPropagation();
              openIp(ip);
            }}
          >
            {ip}
          </EuiLink>
        ) : (
          "—"
        ),
    },
  ].filter(Boolean);

  if (showScore) {
    columns.splice(
      4,
      0,
      {
        field: "score",
        name: "Anomaly score",
        sortable: true,
        width: "120px",
        render: (s) => (s != null ? s.toFixed(4) : "—"),
      },
      // which occupant of the swappable inference slot produced it
      { field: "model", name: "Model", sortable: true, width: "130px", render: (m) => m ?? "—" }
    );
  }

  return (
    <>
      {showTriageFilter && (
        <>
          <EuiFilterGroup compressed>
            {TRIAGE_STATES.map((s) => (
              <EuiFilterButton
                key={s}
                isToggle
                isSelected={triageShown.includes(s)}
                hasActiveFilters={triageShown.includes(s)}
                numFilters={counts[s] ?? 0}
                onClick={() => toggle(s)}
              >
                {s.replace("_", " ")}
              </EuiFilterButton>
            ))}
          </EuiFilterGroup>
          <EuiSpacer size="s" />
        </>
      )}
      <EuiInMemoryTable
        items={items}
        columns={columns}
        loading={loading}
        pagination={{ initialPageSize: 25, pageSizeOptions: [10, 25, 50] }}
        sorting={{ sort: { field: "timestamp", direction: "desc" } }}
        rowProps={(item) => ({
          onClick: () => setSelected(item),
          style: { cursor: "pointer" },
        })}
      />
      <AlertFlyout alert={current} onClose={() => setSelected(null)} onRefresh={onRefresh} />
    </>
  );
}
