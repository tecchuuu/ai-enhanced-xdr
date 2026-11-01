import { useState } from "react";
import {
  EuiPanel,
  EuiBasicTable,
  EuiButton,
  EuiText,
  EuiSpacer,
  EuiEmptyPrompt,
  EuiConfirmModal,
  EuiCallOut,
  EuiCodeBlock,
  EuiBadge,
  EuiToolTip,
  EuiLink,
} from "@elastic/eui";
import { getBlockedIps, unblockIp } from "../api";
import { usePolling } from "../lib/usePolling";
import { fmtTime, refText } from "../lib/format";
import { useNav } from "../lib/nav";
import PanelTitle from "./PanelTitle";

const agentLabel = (row) => row.agent_name ?? `agent ${row.agent_id}`;

// Wazuh's API can't undo a firewall-drop (failure log Entry 45), so an unblock is
// two steps: record the request and remove the rule on the agent by hand, then
// confirm the removal here. Until then the IP stays listed as "unblock pending".
export default function BlockedIps() {
  const { openIp } = useNav();
  const [blocked, setBlocked] = useState(null);
  const [target, setTarget] = useState(null); // row being unblocked or confirmed
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState(null);
  const [notice, setNotice] = useState(null); // the unblock just recorded

  const load = usePolling(async (isCurrent) => {
    try {
      const { blocked } = await getBlockedIps();
      if (isCurrent()) setBlocked(blocked);
    } catch {
      if (isCurrent()) setBlocked([]);
    }
  }, 15000);

  const confirming = Boolean(target?.unblock_unconfirmed);

  const submit = async () => {
    setBusy(true);
    setError(null);
    setNotice(null);
    try {
      const res = await unblockIp({
        agentId: target.agent_id,
        srcip: target.srcip,
        confirm: confirming,
      });
      if (!confirming) {
        setNotice({ ip: target.srcip, agent: agentLabel(target), manual: res.manual });
      }
      setTarget(null);
      load();
    } catch (e) {
      setError(String(e.message ?? e));
    } finally {
      setBusy(false);
    }
  };

  const columns = [
    {
      field: "srcip",
      name: "IP",
      width: "140px",
      render: (ip) => <EuiLink onClick={() => openIp(ip)}>{ip}</EuiLink>,
    },
    {
      field: "agent_name",
      name: "Agent",
      width: "110px",
      render: (name, row) => name ?? row.agent_id ?? "—",
    },
    { field: "since", name: "Blocked since", render: fmtTime, width: "150px" },
    { field: "alert_ref", name: "Triggered by", truncateText: true, render: refText },
    {
      name: "State",
      width: "170px",
      render: (row) =>
        row.unblock_unconfirmed ? (
          <EuiToolTip content="Unblock requested. Wazuh can't remove a firewall block, so the rule stays until it is removed on the agent by hand and the removal is confirmed here.">
            <EuiBadge color="warning">unblock pending</EuiBadge>
          </EuiToolTip>
        ) : (
          <EuiBadge color="hollow">blocked</EuiBadge>
        ),
    },
    {
      name: "Action",
      width: "150px",
      render: (row) => (
        <EuiButton size="s" color="text" onClick={() => setTarget(row)}>
          {row.unblock_unconfirmed ? "Confirm removed" : "Unblock"}
        </EuiButton>
      ),
    },
  ];

  return (
    <EuiPanel hasBorder>
      <PanelTitle
        title="Currently blocked"
        info="IPs currently blocked by Wazuh's firewall-drop response, worked out from the response log. Wazuh's API has no undo for a block, so Unblock records the request and gives the command to remove the rule on the agent; the IP stays listed as 'unblock pending' until the removal is confirmed here."
      />
      <EuiSpacer size="s" />
      {notice && (
        <>
          <EuiCallOut
            title={`Unblock of ${notice.ip} recorded — the rule is still in place`}
            color="warning"
            iconType="warning"
            size="s"
            onDismiss={() => setNotice(null)}
          >
            <p>
              Wazuh can't remove a firewall block, so nothing was sent. Run this on{" "}
              {notice.agent} (inside its container, for a containerised agent), repeating
              until no rule is left, then click <strong>Confirm removed</strong>:
            </p>
            <EuiCodeBlock language="bash" fontSize="s" paddingSize="s" isCopyable>
              {notice.manual}
            </EuiCodeBlock>
          </EuiCallOut>
          <EuiSpacer size="s" />
        </>
      )}
      {blocked?.length === 0 ? (
        <EuiEmptyPrompt
          iconType="check"
          titleSize="xs"
          title={<h3>Nothing blocked</h3>}
          body={<p>IPs blocked from an alert will be listed here with an unblock action.</p>}
        />
      ) : (
        <EuiBasicTable
          items={blocked ?? []}
          columns={columns}
          loading={blocked == null}
        />
      )}
      {target && (
        <EuiConfirmModal
          title={confirming ? `Confirm ${target.srcip} was removed?` : `Unblock ${target.srcip}?`}
          onCancel={() => setTarget(null)}
          onConfirm={submit}
          cancelButtonText="Cancel"
          confirmButtonText={busy ? "Saving…" : confirming ? "Confirm removed" : "Record unblock"}
          confirmButtonDisabled={busy}
          defaultFocusedButton="cancel"
        >
          <EuiText size="s">
            {confirming ? (
              <p>
                Only confirm once the rule for <strong>{target.srcip}</strong> is gone from{" "}
                {agentLabel(target)}. The IP then leaves this list, and the confirmation is
                recorded in the response log under your name.
              </p>
            ) : (
              <p>
                Wazuh can't remove a firewall block, so nothing is sent to{" "}
                {agentLabel(target)}. This records the unblock in the response log and gives
                the command to remove the rule for <strong>{target.srcip}</strong> by hand.
              </p>
            )}
          </EuiText>
          {confirming && target.manual && (
            <>
              <EuiSpacer size="s" />
              <EuiCodeBlock language="bash" fontSize="s" paddingSize="s" isCopyable>
                {target.manual}
              </EuiCodeBlock>
            </>
          )}
          {error && (
            <>
              <EuiSpacer size="s" />
              <EuiCallOut title={error} color="danger" iconType="warning" size="s" />
            </>
          )}
        </EuiConfirmModal>
      )}
    </EuiPanel>
  );
}
