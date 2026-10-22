import { useState } from "react";
import {
  EuiInMemoryTable,
  EuiBasicTable,
  EuiFilterGroup,
  EuiFilterButton,
  EuiLink,
  EuiSpacer,
  EuiButtonIcon,
  EuiIconTip,
  EuiText,
} from "@elastic/eui";
import { SourceBadge, SeverityBadge, TriageBadge, TRIAGE_STATES } from "./badges";
import MitreLink from "./MitreLink";
import { fmtTime, fmtAgo, fmtScore, displayScore, modelLabel } from "../lib/format";
import { useNav } from "../lib/nav";

const PAGE_SIZES = [10, 25, 50, 100];
// what the server can sort a feed by (FEED_SORT in main.py)
const SERVER_SORTABLE = ["timestamp", "level"];

// The alert's name, with its type and ATT&CK technique on a second line —
// the column an analyst reads first gets the width, not the timestamp.
function AlertCell({ a }) {
  const type = a.category ? a.category.replace(/_/g, " ") : null;
  return (
    <div>
      <div>{a.description ?? "—"}</div>
      {(type || a.mitre) && (
        <EuiText size="xs" color="subdued">
          {type}
          {type && a.mitre && " · "}
          {a.mitre && <MitreLink id={a.mitre} tactic={a.tactic} />}
        </EuiText>
      )}
    </div>
  );
}

function TriageFilter({ counts, shown, onToggle }) {
  return (
    <>
      <EuiFilterGroup compressed>
        {TRIAGE_STATES.map((s) => (
          <EuiFilterButton
            key={s}
            isToggle
            isSelected={shown.includes(s)}
            hasActiveFilters={shown.includes(s)}
            numFilters={counts?.[s] ?? 0}
            onClick={() => onToggle(s)}
          >
            {s.replace("_", " ")}
          </EuiFilterButton>
        ))}
      </EuiFilterGroup>
      <EuiSpacer size="s" />
    </>
  );
}

// Two modes.
//  - Given `alerts` alone, the table holds them all: it pages, sorts and
//    filters by review state in the browser (Overview, IP view, queue).
//  - Given `server`, the page fetches one page at a time and the table only
//    reports what the analyst asked for — page, size, sort, review states —
//    so every alert in the range can be reached, and the filter counts cover
//    all of them (the Wazuh alerts and AI detections feeds):
//      server = { pageIndex, pageSize, total, sort: {field, direction},
//                 triageCounts, triageShown, onChange(patch) }
// showSource: off on single-source pages, where every row would say the same
// thing. showWaiting: how long the alert has waited (the queue). The rule id is
// left to the detail panel: a number like 100001 tells a reader nothing the
// name doesn't. initialSort: null keeps the order the alerts came in.
export default function AlertsTable({
  alerts = [],
  loading,
  showScore = false,
  showSource = true,
  showTriageFilter = true,
  showWaiting = false,
  initialSort = { field: "timestamp", direction: "desc" },
  server,
}) {
  const { openIp, openAlert } = useNav();
  const [triageShown, setTriageShown] = useState([]); // empty = every state

  const sortable = (field) => (server ? SERVER_SORTABLE.includes(field) : true);

  const columns = [
    {
      // a keyboard-reachable way in; the whole row is also clickable
      name: "",
      width: "36px",
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
    { field: "timestamp", name: "Time", render: fmtTime, sortable: sortable("timestamp"), width: "140px" },
    showWaiting && {
      name: "Waiting",
      width: "80px",
      render: (a) => fmtAgo(a.timestamp).replace(" ago", ""),
    },
    {
      field: "level",
      name: "Severity",
      render: (level) => <SeverityBadge level={level} />,
      sortable: sortable("level"),
      width: "112px",
    },
    {
      field: "description",
      name: "Alert",
      sortable: sortable("description"),
      render: (_d, a) => <AlertCell a={a} />,
    },
    showScore && {
      field: "score",
      name: (
        <>
          Score{" "}
          <EuiIconTip
            type="info"
            color="subdued"
            size="s"
            content="How unusual the model found this minute — higher is more unusual. Each model has its own scale, so compare scores within one model, not across models."
          />
        </>
      ),
      sortable: server ? false : (a) => displayScore(a.score) ?? -Infinity,
      width: "92px",
      render: fmtScore,
    },
    // which occupant of the swappable inference slot produced it
    showScore && {
      field: "model",
      name: "Model",
      sortable: sortable("model"),
      width: "125px",
      render: modelLabel,
    },
    { field: "agent", name: "Agent", sortable: sortable("agent"), width: "105px" },
    showSource && {
      field: "source",
      name: "Source",
      render: (source) => <SourceBadge source={source} />,
      sortable: sortable("source"),
      width: "80px",
    },
    {
      field: "triage_status",
      name: "Triage",
      render: (s) => <TriageBadge status={s} />,
      sortable: sortable("triage_status"),
      width: "110px",
    },
    {
      field: "srcip",
      name: "Source IP",
      sortable: sortable("srcip"),
      width: "140px",
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
                      ? "Unblock sent but not confirmed — the block may still be in place"
                      : `Blocked on ${a.blocked.agent_name ?? `agent ${a.blocked.agent_id}`} since ${fmtTime(a.blocked.since)}`
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

  const rowProps = (item) => ({
    onClick: () => openAlert(item),
    style: { cursor: "pointer" },
  });

  if (server) {
    const toggle = (s) =>
      server.onChange({
        triageShown: server.triageShown.includes(s)
          ? server.triageShown.filter((x) => x !== s)
          : [...server.triageShown, s],
        pageIndex: 0,
      });
    return (
      <>
        {showTriageFilter && (
          <TriageFilter counts={server.triageCounts} shown={server.triageShown} onToggle={toggle} />
        )}
        <EuiBasicTable
          items={alerts}
          columns={columns}
          loading={loading}
          rowProps={rowProps}
          pagination={{
            pageIndex: server.pageIndex,
            pageSize: server.pageSize,
            // the search engine pages at most 10,000 deep (FEED_MAX in main.py)
            totalItemCount: Math.min(server.total ?? 0, 10000),
            pageSizeOptions: PAGE_SIZES,
          }}
          sorting={{ sort: server.sort }}
          onChange={({ page, sort }) =>
            server.onChange({
              pageIndex: page?.index ?? 0,
              pageSize: page?.size ?? server.pageSize,
              ...(sort && { sort }),
            })
          }
        />
      </>
    );
  }

  const counts = {};
  for (const a of alerts) counts[a.triage_status ?? "new"] = (counts[a.triage_status ?? "new"] ?? 0) + 1;
  const items = triageShown.length
    ? alerts.filter((a) => triageShown.includes(a.triage_status ?? "new"))
    : alerts;
  const toggle = (s) =>
    setTriageShown((t) => (t.includes(s) ? t.filter((x) => x !== s) : [...t, s]));

  return (
    <>
      {showTriageFilter && <TriageFilter counts={counts} shown={triageShown} onToggle={toggle} />}
      <EuiInMemoryTable
        items={items}
        columns={columns}
        loading={loading}
        pagination={{ initialPageSize: 25, pageSizeOptions: PAGE_SIZES }}
        sorting={initialSort ? { sort: initialSort } : true}
        rowProps={rowProps}
      />
    </>
  );
}
