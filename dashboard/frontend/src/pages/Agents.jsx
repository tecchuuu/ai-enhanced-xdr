import { useState } from "react";
import { EuiPanel, EuiInMemoryTable, EuiHealth, EuiCallOut } from "@elastic/eui";
import { getAgents } from "../api";
import { usePolling } from "../lib/usePolling";

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

  usePolling(async (isCurrent) => {
    try {
      const { agents } = await getAgents();
      if (!isCurrent()) return;
      setAgents(agents);
      setError(null);
    } catch (e) {
      if (isCurrent()) setError(String(e.message ?? e));
    }
  }, 30000);

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
