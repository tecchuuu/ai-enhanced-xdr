import { useState } from "react";
import { EuiInMemoryTable } from "@elastic/eui";
import { SourceBadge, SeverityBadge, TriageBadge, TRIAGE_STATES } from "./badges";
import AlertFlyout from "./AlertFlyout";

const fmtTime = (ts) => (ts ? new Date(ts).toLocaleString() : "—");

const TRIAGE_FILTER = {
  type: "field_value_selection",
  field: "triage_status",
  name: "Triage",
  multiSelect: "or",
  options: TRIAGE_STATES.map((s) => ({
    value: s,
    view: <TriageBadge status={s} />,
  })),
};

export default function AlertsTable({ alerts, loading, showScore = false, onRefresh }) {
  const [selected, setSelected] = useState(null);

  // keep the open flyout pointed at the freshest copy of its alert, so a triage
  // save (which refetches upstream) is reflected without reopening
  const current = selected
    ? (alerts?.find((a) => a.id === selected.id) ?? selected)
    : null;

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
    {
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
    { field: "srcip", name: "Source IP", sortable: true, width: "130px" },
  ];

  if (showScore) {
    columns.splice(4, 0, {
      field: "score",
      name: "Anomaly score",
      sortable: true,
      width: "120px",
      render: (s) => (s != null ? s.toFixed(4) : "—"),
    });
  }

  return (
    <>
      <EuiInMemoryTable
        items={alerts}
        columns={columns}
        loading={loading}
        search={{
          box: { incremental: true, placeholder: "Filter alerts…" },
          filters: [TRIAGE_FILTER],
        }}
        pagination={{ initialPageSize: 25, pageSizeOptions: [10, 25, 50] }}
        sorting={{ sort: { field: "timestamp", direction: "desc" } }}
        rowProps={(item) => ({
          onClick: () => setSelected(item),
          style: { cursor: "pointer" },
        })}
      />
      <AlertFlyout
        alert={current}
        onClose={() => setSelected(null)}
        onRefresh={onRefresh}
      />
    </>
  );
}
