import { useState } from "react";
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
  EuiFlexGroup,
  EuiFlexItem,
} from "@elastic/eui";
import { SourceBadge, SeverityBadge } from "./badges";
import BlockIpModal from "./BlockIpModal";

export default function AlertFlyout({ alert, onClose }) {
  const [blocking, setBlocking] = useState(false);
  if (!alert) return null;

  const items = [
    { title: "Timestamp", description: alert.timestamp ?? "—" },
    { title: "Agent", description: alert.agent ?? "—" },
    { title: "Rule ID", description: alert.rule_id ?? "—" },
    { title: "Severity", description: <SeverityBadge level={alert.level} /> },
    { title: "Source", description: <SourceBadge source={alert.source} /> },
  ];

  if (alert.srcip) items.push({ title: "Source IP", description: alert.srcip });
  if (alert.srcuser) items.push({ title: "Source user", description: alert.srcuser });
  if (alert.category) items.push({ title: "Category", description: alert.category });
  if (alert.mitre) items.push({ title: "MITRE ATT&CK", description: alert.mitre });

  // AI-specific: how the model saw the window
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
