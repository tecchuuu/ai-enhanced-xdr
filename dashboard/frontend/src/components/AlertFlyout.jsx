import { useEffect, useState } from "react";
import {
  EuiFlyout,
  EuiFlyoutHeader,
  EuiFlyoutBody,
  EuiFlyoutFooter,
  EuiTitle,
  EuiSpacer,
  EuiDescriptionList,
  EuiCodeBlock,
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
} from "@elastic/eui";
import { SourceBadge, SeverityBadge, TriageBadge, TRIAGE_STATES } from "./badges";
import { setTriage } from "../api";
import BlockIpModal from "./BlockIpModal";
import ExplainPanel from "./ExplainPanel";

const STATUS_OPTIONS = TRIAGE_STATES.map((s) => ({
  id: s,
  label: s === "false_positive" ? "false positive" : s,
}));

export default function AlertFlyout({ alert, onClose, onRefresh }) {
  const [blocking, setBlocking] = useState(false);
  const [status, setStatus] = useState("new");
  const [assignee, setAssignee] = useState("");
  const [note, setNote] = useState("");
  const [saving, setSaving] = useState(false);
  const [saved, setSaved] = useState(false);
  const [error, setError] = useState(null);

  useEffect(() => {
    setStatus(alert?.triage_status ?? "new");
    setAssignee(alert?.assignee ?? "");
    setNote(alert?.triage_note ?? "");
    setSaved(false);
    setError(null);
  }, [alert]);

  if (!alert) return null;

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

  const items = [
    { title: "Timestamp", description: alert.timestamp ?? "—" },
    { title: "Agent", description: alert.agent ?? "—" },
    { title: "Rule ID", description: alert.rule_id ?? "—" },
    { title: "Severity", description: <SeverityBadge level={alert.level} /> },
    { title: "Source", description: <SourceBadge source={alert.source} /> },
    { title: "Triage", description: <TriageBadge status={alert.triage_status} /> },
  ];

  if (alert.srcip) items.push({ title: "Source IP", description: alert.srcip });
  if (alert.srcuser) items.push({ title: "Source user", description: alert.srcuser });
  if (alert.category) items.push({ title: "Category", description: alert.category });
  if (alert.mitre) items.push({ title: "MITRE ATT&CK", description: alert.mitre });

  if (alert.source === "ai") {
    items.push(
      { title: "Anomaly score", description: String(alert.score ?? "—") },
      { title: "Events in window", description: String(alert.event_count ?? "—") },
      { title: "Distinct users", description: String(alert.distinct_users ?? "—") }
    );
    if (alert.top_srcips?.length) {
      items.push({
        title: "Top source IPs",
        description: alert.top_srcips.map((t) => `${t.ip} (${t.count})`).join(", "),
      });
    }
  }

  return (
    <EuiFlyout onClose={onClose} size="m" ownFocus>
      <EuiFlyoutHeader hasBorder>
        <EuiTitle size="s">
          <h2>{alert.description ?? "Alert detail"}</h2>
        </EuiTitle>
        <EuiSpacer size="xs" />
        <EuiText size="s" color="subdued">
          {alert.source === "ai"
            ? "Flagged by the anomaly model — no signature involved."
            : "Matched a Wazuh ruleset signature."}
        </EuiText>
      </EuiFlyoutHeader>
      <EuiFlyoutBody>
        <EuiPanel hasBorder color="subdued">
          <EuiTitle size="xxs">
            <h3>Triage</h3>
          </EuiTitle>
          <EuiSpacer size="s" />
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
            {alert.source === "ai" && (
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

        {alert.source === "ai" && (
          <>
            <EuiSpacer />
            <ExplainPanel alert={alert} onRefresh={onRefresh} />
          </>
        )}

        <EuiSpacer />
        <EuiDescriptionList type="column" listItems={items} compressed />
        <EuiSpacer />
        <EuiTitle size="xxs">
          <h3>Raw document</h3>
        </EuiTitle>
        <EuiSpacer size="s" />
        <EuiCodeBlock language="json" fontSize="s" paddingSize="s" isCopyable>
          {JSON.stringify(alert, null, 2)}
        </EuiCodeBlock>
      </EuiFlyoutBody>
      {alert.srcip && (
        <EuiFlyoutFooter>
          <EuiFlexGroup justifyContent="flexEnd">
            <EuiFlexItem grow={false}>
              <EuiButton
                color="danger"
                iconType="securitySignalDetected"
                onClick={() => setBlocking(true)}
              >
                Block {alert.srcip}
              </EuiButton>
            </EuiFlexItem>
          </EuiFlexGroup>
        </EuiFlyoutFooter>
      )}
      {blocking && (
        <BlockIpModal
          srcip={alert.srcip}
          alertRef={`${alert.rule_id ?? "?"} — ${alert.description ?? ""}`}
          defaultAgentName={alert.agent}
          onClose={() => setBlocking(false)}
        />
      )}
    </EuiFlyout>
  );
}
