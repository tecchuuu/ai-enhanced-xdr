import { useEffect, useState } from "react";
import {
  EuiFlyout,
  EuiFlyoutHeader,
  EuiFlyoutBody,
  EuiFlyoutFooter,
  EuiTitle,
  EuiSpacer,
  EuiDescriptionList,
  EuiLink,
  EuiText,
  EuiButton,
  EuiButtonEmpty,
  EuiButtonGroup,
  EuiFieldText,
  EuiTextArea,
  EuiFormRow,
  EuiPanel,
  EuiCallOut,
  EuiFlexGroup,
  EuiFlexItem,
  EuiTabs,
  EuiTab,
  EuiBadge,
} from "@elastic/eui";
import { SourceBadge, SeverityBadge, TriageBadge, TRIAGE_STATES } from "./badges";
import { setTriage } from "../api";
import { fmtTime } from "../lib/format";
import { useNav } from "../lib/nav";
import BlockIpModal from "./BlockIpModal";
import ExplainPanel from "./ExplainPanel";
import RelatedEvents from "./RelatedEvents";
import RawDocument from "./RawDocument";
import WhyItFired from "./WhyItFired";
import MitreLink from "./MitreLink";

const STATUS_OPTIONS = TRIAGE_STATES.map((s) => ({
  id: s,
  label: s === "false_positive" ? "false positive" : s,
}));

// An AI detection covers a window, not an instant: "10:01:00 – 10:02:00"
function when(alert) {
  if (!alert.timestamp) return "—";
  const secs = Number(/^(\d+)s$/.exec(alert.window ?? "")?.[1]);
  if (alert.source !== "ai" || !secs) return fmtTime(alert.timestamp);
  const end = new Date(Date.parse(alert.timestamp) + secs * 1000);
  return `${fmtTime(alert.timestamp)} – ${end.toLocaleTimeString()}`;
}

export default function AlertFlyout({ alert, onClose, onRefresh }) {
  const { openIp, goto } = useNav();
  const [blocking, setBlocking] = useState(false);
  const [status, setStatus] = useState("new");
  const [assignee, setAssignee] = useState("");
  const [note, setNote] = useState("");
  const [saving, setSaving] = useState(false);
  const [saved, setSaved] = useState(false);
  const [error, setError] = useState(null);
  // a tab mounts the first time it's opened and stays mounted (hidden) after,
  // so the assistant's Q&A and an unsaved triage note survive switching tabs,
  // and Related / JSON only load when someone looks at them
  const [tab, setTab] = useState("overview");
  const [visited, setVisited] = useState(["overview"]);

  // reset only when a different alert is opened — refreshes hand us a fresh
  // object for the same alert, which would otherwise wipe unsaved input
  useEffect(() => {
    setStatus(alert?.triage_status ?? "new");
    setAssignee(alert?.assignee ?? "");
    setNote(alert?.triage_note ?? "");
    setSaved(false);
    setError(null);
    setTab("overview");
    setVisited(["overview"]);
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [alert?.id]);

  if (!alert) return null;

  const isAi = alert.source === "ai";
  const tabs = [
    { id: "overview", name: "Overview" },
    { id: "triage", name: "Triage" },
    ...(isAi ? [{ id: "assistant", name: "Assistant" }] : []),
    { id: "related", name: "Related events" },
    { id: "json", name: "JSON" },
  ];
  const open = (id) => {
    setTab(id);
    setVisited((v) => (v.includes(id) ? v : [...v, id]));
  };
  const panel = (id, content) =>
    visited.includes(id) && (
      <div key={id} hidden={tab !== id}>
        {content}
      </div>
    );

  const save = async (overrideStatus) => {
    const nextStatus = overrideStatus ?? status;
    setSaving(true);
    setError(null);
    try {
      await setTriage({
        alertId: alert.id,
        status: nextStatus,
        assignee: assignee || null,
        note: note || null,
        falsePositive: nextStatus === "false_positive",
        alertRef: `${alert.rule_id ?? "?"} — ${alert.description ?? ""}`,
        alertTimestamp: alert.timestamp,
        alertSource: alert.source,
        alertAgent: alert.agent,
      });
      setStatus(nextStatus);
      setSaved(true);
      onRefresh?.();
    } catch (e) {
      setError(String(e.message ?? e));
    } finally {
      setSaving(false);
    }
  };

  const ipLink = (ip) => <EuiLink onClick={() => openIp(ip)}>{ip}</EuiLink>;
  const items = [
    { title: isAi ? "Window" : "Time", description: when(alert) },
    { title: "Agent", description: alert.agent ?? "—" },
    { title: "Rule ID", description: alert.rule_id ?? "—" },
  ];
  if (alert.srcip) items.push({ title: "Source IP", description: ipLink(alert.srcip) });
  if (alert.srcuser) items.push({ title: "Source user", description: alert.srcuser });
  if (alert.dstuser) items.push({ title: "Target user", description: alert.dstuser });
  if (alert.category) items.push({ title: "Category", description: alert.category.replace(/_/g, " ") });
  if (alert.mitre)
    items.push({
      title: "MITRE ATT&CK",
      description: (
        <>
          <MitreLink id={alert.mitre} />
          {alert.tactic && ` · ${alert.tactic}`}
        </>
      ),
    });

  if (isAi) {
    items.push(
      { title: "Model", description: alert.model ?? "—" },
      { title: "Anomaly score", description: String(alert.score ?? "—") }
    );
    // each lane windows a different feature set (ROADMAP rule 1)
    if (alert.pipeline === "web-streaming") {
      items.push(
        { title: "Requests in window", description: String(alert.request_count ?? "—") },
        { title: "Distinct URLs", description: String(alert.distinct_urls ?? "—") },
        { title: "Error ratio", description: String(alert.error_ratio ?? "—") },
        { title: "404 responses", description: String(alert.not_found_count ?? "—") },
        { title: "POST ratio", description: String(alert.post_ratio ?? "—") }
      );
      if (alert.top_urls?.length) {
        items.push({
          title: "Top URLs",
          description: alert.top_urls.map((u) => (
            <div key={u.url}>
              {u.url} ({u.count})
            </div>
          )),
        });
      }
    } else {
      items.push(
        { title: "Events in window", description: String(alert.event_count ?? "—") },
        { title: "Distinct users", description: String(alert.distinct_users ?? "—") },
        { title: "Events per user", description: String(alert.events_per_user ?? "—") }
      );
    }
    if (alert.top_srcips?.length) {
      items.push({
        title: "Top source IPs",
        description: alert.top_srcips.map((t, i) => (
          <span key={t.ip}>
            {i > 0 && ", "}
            {ipLink(t.ip)} ({t.count})
          </span>
        )),
      });
    }
  }

  return (
    <EuiFlyout onClose={onClose} size="m" ownFocus aria-labelledby="alert-flyout-title">
      <EuiFlyoutHeader hasBorder>
        <EuiTitle size="s">
          <h2 id="alert-flyout-title">{alert.description ?? "Alert detail"}</h2>
        </EuiTitle>
        <EuiSpacer size="xs" />
        <EuiText size="s" color="subdued">
          {isAi
            ? "Flagged by the anomaly model — no signature involved."
            : "Matched a Wazuh ruleset signature."}
        </EuiText>
        <EuiSpacer size="s" />
        <EuiFlexGroup gutterSize="xs" responsive={false} wrap>
          <EuiFlexItem grow={false}>
            <SeverityBadge level={alert.level} />
          </EuiFlexItem>
          <EuiFlexItem grow={false}>
            <SourceBadge source={alert.source} />
          </EuiFlexItem>
          <EuiFlexItem grow={false}>
            <TriageBadge status={alert.triage_status} />
          </EuiFlexItem>
          {alert.blocked && (
            <EuiFlexItem grow={false}>
              <EuiBadge color={alert.blocked.unblock_unconfirmed ? "warning" : "danger"} iconType="lock">
                {alert.blocked.unblock_unconfirmed ? "unblock unconfirmed" : "source blocked"}
              </EuiBadge>
            </EuiFlexItem>
          )}
        </EuiFlexGroup>
        <EuiSpacer size="s" />
        <EuiTabs bottomBorder={false} size="s" style={{ marginBottom: -17 }}>
          {tabs.map((t) => (
            <EuiTab key={t.id} isSelected={tab === t.id} onClick={() => open(t.id)}>
              {t.name}
            </EuiTab>
          ))}
        </EuiTabs>
      </EuiFlyoutHeader>
      <EuiFlyoutBody>
        {panel(
          "overview",
          <>
            {isAi && (
              <>
                <WhyItFired alert={alert} />
                <EuiSpacer />
              </>
            )}
            <EuiDescriptionList type="column" listItems={items} compressed />
          </>
        )}
        {panel(
          "triage",
          <EuiPanel hasBorder color="subdued">
            <EuiFormRow label="Status" fullWidth>
              <EuiButtonGroup
                legend="Triage status"
                options={STATUS_OPTIONS}
                idSelected={status}
                onChange={setStatus}
                buttonSize="compressed"
              />
            </EuiFormRow>
            <EuiFormRow label="Assignee" fullWidth>
              <EuiFieldText
                placeholder="analyst"
                value={assignee}
                onChange={(e) => setAssignee(e.target.value)}
                compressed
                fullWidth
              />
            </EuiFormRow>
            <EuiFormRow label="Note" fullWidth>
              <EuiTextArea
                placeholder="What did you find?"
                value={note}
                onChange={(e) => setNote(e.target.value)}
                rows={3}
                compressed
                fullWidth
              />
            </EuiFormRow>
            <EuiFlexGroup gutterSize="s" alignItems="center" responsive={false} wrap>
              <EuiFlexItem grow={false}>
                <EuiButton size="s" onClick={() => save()} isLoading={saving} fill>
                  Save triage
                </EuiButton>
              </EuiFlexItem>
              {isAi && (
                <EuiFlexItem grow={false}>
                  <EuiButtonEmpty
                    size="s"
                    color="warning"
                    onClick={() => save("false_positive")}
                    isDisabled={saving}
                  >
                    Mark false positive
                  </EuiButtonEmpty>
                </EuiFlexItem>
              )}
              {saved && !error && (
                <EuiFlexItem grow={false}>
                  <EuiText size="xs" color="success">
                    saved
                  </EuiText>
                </EuiFlexItem>
              )}
            </EuiFlexGroup>
            {error && (
              <>
                <EuiSpacer size="s" />
                <EuiCallOut title={error} color="danger" iconType="warning" size="s" />
              </>
            )}
          </EuiPanel>
        )}
        {isAi && panel("assistant", <ExplainPanel alert={alert} onRefresh={onRefresh} />)}
        {panel("related", <RelatedEvents alert={alert} />)}
        {panel("json", <RawDocument key={alert.id} alertId={alert.id} />)}
      </EuiFlyoutBody>
      {alert.srcip && (
        <EuiFlyoutFooter>
          <EuiFlexGroup justifyContent="flexEnd" alignItems="center" responsive={false}>
            {alert.blocked ? (
              <>
                <EuiFlexItem grow={false}>
                  <EuiText size="s" color="subdued">
                    {alert.blocked.unblock_unconfirmed ? "Unblock not confirmed for" : "Blocked:"}{" "}
                    {alert.srcip} on agent {alert.blocked.agent_id} since{" "}
                    {fmtTime(alert.blocked.since)}
                  </EuiText>
                </EuiFlexItem>
                <EuiFlexItem grow={false}>
                  <EuiButtonEmpty
                    size="s"
                    iconType="sortRight"
                    iconSide="right"
                    onClick={() => goto({ page: "responses", alert: null, ip: null })}
                  >
                    Response log
                  </EuiButtonEmpty>
                </EuiFlexItem>
              </>
            ) : (
              <EuiFlexItem grow={false}>
                <EuiButton
                  color="danger"
                  iconType="securitySignalDetected"
                  onClick={() => setBlocking(true)}
                >
                  Block {alert.srcip}
                </EuiButton>
              </EuiFlexItem>
            )}
          </EuiFlexGroup>
        </EuiFlyoutFooter>
      )}
      {blocking && (
        <BlockIpModal
          srcip={alert.srcip}
          alertRef={`${alert.rule_id ?? "?"} — ${alert.description ?? ""}`}
          defaultAgentName={alert.agent}
          onClose={() => {
            setBlocking(false);
            onRefresh?.(); // the footer and the tables pick up the new block
          }}
        />
      )}
    </EuiFlyout>
  );
}
