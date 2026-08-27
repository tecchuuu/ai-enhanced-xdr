import { useState } from "react";
import { EuiPanel, EuiSpacer, EuiFilterGroup, EuiFilterButton } from "@elastic/eui";
import AlertsTable from "../components/AlertsTable";

export default function SecurityEvents({ combined, loading, onRefresh }) {
  const [sourceFilter, setSourceFilter] = useState("all"); // all | rule | ai

  const alerts = (combined?.alerts ?? []).filter(
    (a) => sourceFilter === "all" || a.source === sourceFilter
  );

  return (
    <EuiPanel hasBorder>
      <EuiFilterGroup compressed>
        <EuiFilterButton
          hasActiveFilters={sourceFilter === "all"}
          onClick={() => setSourceFilter("all")}
        >
          All
        </EuiFilterButton>
        <EuiFilterButton
          hasActiveFilters={sourceFilter === "rule"}
          onClick={() => setSourceFilter("rule")}
        >
          Rule-based
        </EuiFilterButton>
        <EuiFilterButton
          hasActiveFilters={sourceFilter === "ai"}
          onClick={() => setSourceFilter("ai")}
        >
          AI model
        </EuiFilterButton>
      </EuiFilterGroup>
      <EuiSpacer size="s" />
      <AlertsTable alerts={alerts} loading={loading} onRefresh={onRefresh} />
    </EuiPanel>
  );
}
