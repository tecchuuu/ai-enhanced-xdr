import { useEffect, useState } from "react";
import {
  EuiPanel,
  EuiInMemoryTable,
  EuiBadge,
  EuiTitle,
  EuiText,
  EuiSpacer,
  EuiEmptyPrompt,
} from "@elastic/eui";
import { getResponseLog } from "../api";
import BlockedIps from "../components/BlockedIps";

const STATUS_COLOR = { executed: "success", refused: "warning", failed: "danger" };
const fmtTime = (ts) => (ts ? new Date(ts).toLocaleString() : "—");

export default function ResponseLog() {
  const [actions, setActions] = useState(null);

  useEffect(() => {
    const load = () =>
      getResponseLog().then(({ actions }) => setActions(actions)).catch(() => {});
    load();
    const t = setInterval(load, 15000);
    return () => clearInterval(t);
  }, []);

  const columns = [
    { field: "timestamp", name: "Time", render: fmtTime, sortable: true, width: "170px" },
    { field: "action", name: "Action", width: "110px" },
    { field: "srcip", name: "Target IP", width: "130px" },
    { field: "agent_id", name: "Agent", width: "80px" },
    {
      field: "status",
      name: "Status",
      width: "110px",
      render: (s) => <EuiBadge color={STATUS_COLOR[s] ?? "hollow"}>{s}</EuiBadge>,
    },
    { field: "alert_ref", name: "Triggered by", truncateText: true },
    { field: "detail", name: "Detail", truncateText: true },
  ];

  return (
    <>
      <BlockedIps />
      <EuiSpacer />
      <EuiPanel hasBorder>
      <EuiTitle size="xs">
        <h2>Response actions</h2>
      </EuiTitle>
      <EuiText size="s" color="subdued">
        <p>
          Every action initiated from this console, including refusals — the audit trail
          lives in <code>ai-responses-*</code>.
        </p>
      </EuiText>
      <EuiSpacer size="s" />
      {actions?.length === 0 ? (
        <EuiEmptyPrompt
          iconType="securitySignalDetected"
          titleSize="xs"
          title={<h3>No actions taken yet</h3>}
          body={<p>Block an IP from an alert's detail panel and it will appear here.</p>}
        />
      ) : (
        <EuiInMemoryTable
          items={actions ?? []}
          columns={columns}
          loading={actions == null}
          pagination={{ initialPageSize: 25 }}
          sorting={{ sort: { field: "timestamp", direction: "desc" } }}
        />
      )}
      </EuiPanel>
    </>
  );
}
