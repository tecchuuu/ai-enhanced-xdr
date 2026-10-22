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
  EuiBadge,
  EuiToolTip,
  EuiLink,
} from "@elastic/eui";
import { getBlockedIps, unblockIp } from "../api";
import { usePolling } from "../lib/usePolling";
import { fmtTime, refText } from "../lib/format";
import { useNav } from "../lib/nav";
import PanelTitle from "./PanelTitle";

export default function BlockedIps() {
  const { openIp } = useNav();
  const [blocked, setBlocked] = useState(null);
  const [target, setTarget] = useState(null); // row pending unblock
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState(null);
  const [notice, setNotice] = useState(null); // unblock Wazuh didn't accept

  const load = usePolling(async (isCurrent) => {
    try {
      const { blocked } = await getBlockedIps();
      if (isCurrent()) setBlocked(blocked);
    } catch {
      if (isCurrent()) setBlocked([]);
    }
  }, 15000);

  const confirmUnblock = async () => {
    setBusy(true);
    setError(null);
    setNotice(null);
    try {
      const res = await unblockIp({ agentId: target.agent_id, srcip: target.srcip });
      if (res.confirmed === false) {
        setNotice(
          `Wazuh did not confirm the unblock of ${target.srcip} on ${target.agent_name ?? `agent ${target.agent_id}`}. ` +
            "The drop may still be in place, so it stays listed — remove it on the agent " +
            "(iptables -D) or retry. Details are in the response log."
        );
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
          <EuiToolTip content="An unblock was sent but Wazuh did not accept it — the drop may still be in place on the agent.">
            <EuiBadge color="warning">unblock unconfirmed</EuiBadge>
          </EuiToolTip>
        ) : (
          <EuiBadge color="hollow">blocked</EuiBadge>
        ),
    },
    {
      name: "Action",
      width: "140px",
      render: (row) => (
        <EuiButton size="s" color="text" onClick={() => setTarget(row)}>
          {row.unblock_unconfirmed ? "Retry unblock" : "Unblock"}
        </EuiButton>
      ),
    },
  ];

  return (
    <EuiPanel hasBorder>
      <PanelTitle
        title="Currently blocked"
        info="IPs currently blocked by Wazuh's firewall-drop response, worked out from the response log. Unblocking is best-effort — Wazuh has no proper undo. If Wazuh does not confirm an unblock, the IP stays listed as 'unblock unconfirmed'."
      />
      <EuiSpacer size="s" />
      {notice && (
        <>
          <EuiCallOut
            title={notice}
            color="warning"
            iconType="warning"
            size="s"
            onDismiss={() => setNotice(null)}
          />
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
          title={`Unblock ${target.srcip}?`}
          onCancel={() => setTarget(null)}
          onConfirm={confirmUnblock}
          cancelButtonText="Cancel"
          confirmButtonText={busy ? "Unblocking…" : "Unblock"}
          confirmButtonDisabled={busy}
          defaultFocusedButton="cancel"
        >
          <EuiText size="s">
            <p>
              Removes the firewall block on <strong>{target.srcip}</strong> on{" "}
              {target.agent_name ?? `agent ${target.agent_id}`} and records it in the response log.
            </p>
          </EuiText>
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
