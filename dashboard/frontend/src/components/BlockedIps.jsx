import { useCallback, useEffect, useState } from "react";
import {
  EuiPanel,
  EuiBasicTable,
  EuiButton,
  EuiTitle,
  EuiText,
  EuiSpacer,
  EuiEmptyPrompt,
  EuiConfirmModal,
  EuiCallOut,
} from "@elastic/eui";
import { getBlockedIps, unblockIp } from "../api";

const fmtTime = (ts) => (ts ? new Date(ts).toLocaleString() : "—");

export default function BlockedIps() {
  const [blocked, setBlocked] = useState(null);
  const [target, setTarget] = useState(null); // row pending unblock
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState(null);

  const load = useCallback(() => {
    getBlockedIps()
      .then(({ blocked }) => setBlocked(blocked))
      .catch(() => setBlocked([]));
  }, []);

  useEffect(() => {
    load();
    const t = setInterval(load, 15000);
    return () => clearInterval(t);
  }, [load]);

  const confirmUnblock = async () => {
    setBusy(true);
    setError(null);
    try {
      await unblockIp({ agentId: target.agent_id, srcip: target.srcip });
      setTarget(null);
      load();
    } catch (e) {
      setError(String(e.message ?? e));
    } finally {
      setBusy(false);
    }
  };

  const columns = [
    { field: "srcip", name: "IP", width: "140px" },
    { field: "agent_id", name: "Agent", width: "90px" },
    { field: "since", name: "Blocked since", render: fmtTime, width: "180px" },
    { field: "alert_ref", name: "Triggered by", truncateText: true },
    {
      name: "Action",
      width: "120px",
      render: (row) => (
        <EuiButton size="s" color="text" onClick={() => setTarget(row)}>
          Unblock
        </EuiButton>
      ),
    },
  ];

  return (
    <EuiPanel hasBorder>
      <EuiTitle size="xs">
        <h2>Currently blocked</h2>
      </EuiTitle>
      <EuiText size="s" color="subdued">
        <p>
          Active <code>firewall-drop</code> blocks, derived from the response audit log.
          Unblock is best-effort — Wazuh has no first-class API undo, so a persistent
          drop may need removing on the agent.
        </p>
      </EuiText>
      <EuiSpacer size="s" />
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
              Removes the firewall drop for <strong>{target.srcip}</strong> on agent{" "}
              {target.agent_id} and records the action in the response log.
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
