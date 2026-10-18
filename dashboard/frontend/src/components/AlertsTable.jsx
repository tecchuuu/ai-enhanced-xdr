import { useState } from "react";
import {
  EuiInMemoryTable,
  EuiFilterGroup,
  EuiFilterButton,
  EuiLink,
  EuiSpacer,
  EuiButtonIcon,
  EuiIconTip,
} from "@elastic/eui";
import { SourceBadge, SeverityBadge, TriageBadge, TRIAGE_STATES } from "./badges";
import MitreLink from "./MitreLink";
import { fmtTime } from "../lib/format";
import { useNav } from "../lib/nav";

// showSource: off on single-source pages, where every row would say the same thing.
// Searching is the page's job (server-side, see FeedSearch); the table only
// filters what it was given by triage state. Opening an alert goes through the
// URL (App renders the one alert flyout), so every alert has a link.
export default function AlertsTable({
  alerts = [],
  loading,
  showScore = false,
  showSource = true,
  showTriageFilter = true,
}) {
  const { openIp, openAlert } = useNav();
  const [triageShown, setTriageShown] = useState([]); // empty = every state

  const counts = {};
  for (const a of alerts) counts[a.triage_status ?? "new"] = (counts[a.triage_status ?? "new"] ?? 0) + 1;
  const items = triageShown.length
    ? alerts.filter((a) => triageShown.includes(a.triage_status ?? "new"))
    : alerts;
  const toggle = (s) =>
    setTriageShown((t) => (t.includes(s) ? t.filter((x) => x !== s) : [...t, s]));

  const columns = [
    {
      // a keyboard-reachable way in; the whole row is also clickable
      name: "",
      width: "40px",
      render: (a) => (
        <EuiButtonIcon
          iconType="inspect"
          aria-label={`Open alert: ${a.description ?? a.id}`}
          onClick={(e) => {
            e.stopPropagation();
            openAlert(a);
          }}
        />
      ),
    },
    { field: "timestamp", name: "Time", render: fmtTime, sortable: true, width: "170px" },
    { field: "agent", name: "Agent", sortable: true, width: "110px" },
    { field: "rule_id", name: "Rule ID", sortable: true, width: "80px" },
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
      width: "140px",
      render: (c) => (c ? c.replace(/_/g, " ") : "—"),
    },
    {
      field: "mitre",
      name: "MITRE",
      sortable: true,
      width: "100px",
      render: (id, a) => <MitreLink id={id} tactic={a.tactic} />,
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
      width: "150px",
      // the IP pivot, without also opening the row's alert
      render: (ip, a) =>
        ip ? (
          <span>
            <EuiLink
              onClick={(e) => {
                e.stopPropagation();
                openIp(ip);
              }}
            >
              {ip}
            </EuiLink>
            {a.blocked && (
              <>
                {" "}
                <EuiIconTip
                  type="lock"
                  color={a.blocked.unblock_unconfirmed ? "warning" : "danger"}
                  content={
                    a.blocked.unblock_unconfirmed
                      ? "Unblock sent but not confirmed — the drop may still be in place"
                      : `Blocked on agent ${a.blocked.agent_id} since ${fmtTime(a.blocked.since)}`
                  }
                  aria-label="blocked"
                />
              </>
            )}
          </span>
        ) : (
          "—"
        ),
    },
  ].filter(Boolean);

  if (showScore) {
    columns.splice(
      5,
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
          onClick: () => openAlert(item),
          style: { cursor: "pointer" },
        })}
      />
    </>
  );
}
