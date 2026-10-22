import { useState } from "react";
import {
  EuiInMemoryTable,
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
import { fmtTime, fmtScore, displayScore, modelLabel } from "../lib/format";
import { useNav } from "../lib/nav";

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

// showSource: off on single-source pages, where every row would say the same thing.
// Searching is the page's job (server-side, see FeedSearch); the table only
// filters what it was given by triage state. Opening an alert goes through the
// URL (App renders the one alert flyout), so every alert has a link.
// The rule id is left to the alert's detail panel: a number like 100001 tells
// a reader nothing the name doesn't.
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
    { field: "timestamp", name: "Time", render: fmtTime, sortable: true, width: "140px" },
    {
      field: "level",
      name: "Severity",
      render: (level) => <SeverityBadge level={level} />,
      sortable: true,
      width: "112px",
    },
    { field: "description", name: "Alert", sortable: true, render: (_d, a) => <AlertCell a={a} /> },
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
      sortable: (a) => displayScore(a.score) ?? -Infinity,
      width: "92px",
      render: fmtScore,
    },
    // which occupant of the swappable inference slot produced it
    showScore && { field: "model", name: "Model", sortable: true, width: "125px", render: modelLabel },
    { field: "agent", name: "Agent", sortable: true, width: "105px" },
    showSource && {
      field: "source",
      name: "Source",
      render: (source) => <SourceBadge source={source} />,
      sortable: true,
      width: "80px",
    },
    {
      field: "triage_status",
      name: "Triage",
      render: (s) => <TriageBadge status={s} />,
      sortable: true,
      width: "110px",
    },
    {
      field: "srcip",
      name: "Source IP",
      sortable: true,
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
