import { useState } from "react";
import {
  EuiPanel,
  EuiInMemoryTable,
  EuiBadge,
  EuiSpacer,
  EuiEmptyPrompt,
} from "@elastic/eui";
import { getResponseLog } from "../api";
import { usePolling } from "../lib/usePolling";
import { fmtTime } from "../lib/format";
import BlockedIps from "../components/BlockedIps";
import PanelTitle from "../components/PanelTitle";

const STATUS_COLOR = {
  executed: "success",
  unconfirmed: "warning",
  refused: "warning",
  failed: "danger",
};

export default function ResponseLog() {
  const [actions, setActions] = useState(null);

  usePolling(async (isCurrent) => {
    try {
      const { actions } = await getResponseLog();
      if (isCurrent()) setActions(actions);
    } catch {
      /* header health indicator already reports API problems */
    }
  }, 15000);

  const columns = [
    { field: "timestamp", name: "Time", render: fmtTime, sortable: true, width: "170px" },
    { field: "action", name: "Action", width: "110px" },
    { field: "srcip", name: "Target IP", width: "130px" },
    { field: "agent_id", name: "Agent", width: "80px" },
    { field: "initiated_by", name: "By", width: "110px", render: (by) => by ?? "—" },
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
      <PanelTitle
        title="Response actions"
        info="Every action initiated from this console, refusals included, with who did it. The audit trail lives in the ai-responses-* indices."
      />
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
