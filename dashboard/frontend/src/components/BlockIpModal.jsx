import { useEffect, useState } from "react";
import {
  EuiConfirmModal,
  EuiFormRow,
  EuiSelect,
  EuiText,
  EuiSpacer,
  EuiCallOut,
} from "@elastic/eui";
import { getAgents, blockIp } from "../api";

export default function BlockIpModal({ srcip, alertRef, defaultAgentName, onClose }) {
  const [agents, setAgents] = useState([]);
  const [agentId, setAgentId] = useState("");
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState(null);
  const [done, setDone] = useState(false);

  useEffect(() => {
    getAgents()
      .then(({ agents }) => {
        // the manager (000) can't run agent-side firewall-drop on endpoints
        const real = agents.filter((a) => a.id !== "000");
        setAgents(real);
        const match = real.find((a) => a.name === defaultAgentName);
        setAgentId((match ?? real[0])?.id ?? "");
      })
      .catch((e) => setError(String(e.message ?? e)));
  }, [defaultAgentName]);

  const confirm = async () => {
    setBusy(true);
    setError(null);
    try {
      await blockIp({ agentId, srcip, alertRef, reason: "manual block from dashboard" });
      setDone(true);
    } catch (e) {
      setError(String(e.message ?? e));
    } finally {
      setBusy(false);
    }
  };

  if (done) {
    return (
      <EuiConfirmModal
        title="IP blocked"
        onCancel={onClose}
        onConfirm={onClose}
        confirmButtonText="Close"
        cancelButtonText="Close"
        defaultFocusedButton="confirm"
      >
        <EuiCallOut
          title={`firewall-drop executed for ${srcip}`}
          color="success"
          iconType="check"
          size="s"
        >
          <p>The action is recorded in the Response log.</p>
        </EuiCallOut>
      </EuiConfirmModal>
    );
  }

  return (
    <EuiConfirmModal
      title={`Block ${srcip}?`}
      onCancel={onClose}
      onConfirm={confirm}
      cancelButtonText="Cancel"
      confirmButtonText={busy ? "Blocking…" : "Block IP"}
      buttonColor="danger"
      confirmButtonDisabled={busy || !agentId}
      defaultFocusedButton="cancel"
    >
      <EuiText size="s">
        <p>
          Sends Wazuh's <code>firewall-drop</code> active response to the selected agent —
          the endpoint's firewall will drop all traffic from <strong>{srcip}</strong>.
          The action is audit-logged.
        </p>
      </EuiText>
      <EuiSpacer size="s" />
      <EuiFormRow label="Target agent">
        <EuiSelect
          options={agents.map((a) => ({
            value: a.id,
            text: `${a.name} (${a.id}) — ${a.status}`,
          }))}
          value={agentId}
          onChange={(e) => setAgentId(e.target.value)}
        />
      </EuiFormRow>
      {error && (
        <>
          <EuiSpacer size="s" />
          <EuiCallOut title={error} color="danger" iconType="warning" size="s" />
        </>
      )}
    </EuiConfirmModal>
  );
}
