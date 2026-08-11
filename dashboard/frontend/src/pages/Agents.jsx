import { useEffect, useState } from "react";
import {
  EuiPanel,
  EuiInMemoryTable,
  EuiHealth,
  EuiTitle,
  EuiText,
  EuiSpacer,
  EuiCallOut,
} from "@elastic/eui";
import { getAgents } from "../api";

const STATUS_COLOR = {
  active: "success",
  disconnected: "danger",
  pending: "warning",
  never_connected: "subdued",
};

const fmtKeepAlive = (ts) => {
  if (!ts) return "—";
  // the manager reports a sentinel date for itself
  if (ts.startsWith("9999")) return "n/a (manager)";
  return new Date(ts).toLocaleString();
};

export default function Agents() {
  const [agents, setAgents] = useState(null);
  const [error, setError] = useState(null);

  useEffect(() => {
    const load = () =>
      getAgents()
        .then(({ agents }) => {
          setAgents(agents);
          setError(null);
        })
        .catch((e) => setError(String(e.message ?? e)));
    load();
    const t = setInterval(load, 30000);
    return () => clearInterval(t);
  }, []);

  const columns = [
    { field: "id", name: "ID", width: "60px", sortable: true },
    { field: "name", name: "Name", sortable: true },
    { field: "ip", name: "IP", width: "130px" },
    {
      field: "status",
      name: "Status",
      width: "150px",
      sortable: true,
      render: (s) => <EuiHealth color={STATUS_COLOR[s] ?? "subdued"}>{s}</EuiHealth>,
    },
    { field: "os", name: "OS", render: (os) => (os ? `${os.name} ${os.version ?? ""}` : "—") },
    { field: "version", name: "Agent version", width: "150px" },
    { field: "lastKeepAlive", name: "Last keep-alive", render: fmtKeepAlive, width: "180px" },
  ];

  return (
    <EuiPanel hasBorder>
      <EuiTitle size="xs">
        <h2>Monitored endpoints</h2>
      </EuiTitle>
      <EuiText size="s" color="subdued">
        <p>Live inventory from the Wazuh manager API. Refreshes every 30s.</p>
      </EuiText>
      <EuiSpacer size="s" />
      {error ? (
        <EuiCallOut title={`Wazuh API error: ${error}`} color="danger" iconType="warning" />
      ) : (
        <EuiInMemoryTable
          items={agents ?? []}
          columns={columns}
          loading={agents == null}
          sorting={{ sort: { field: "id", direction: "asc" } }}
        />
      )}
    </EuiPanel>
  );
}
