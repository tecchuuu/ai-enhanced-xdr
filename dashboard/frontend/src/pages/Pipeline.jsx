import { useState } from "react";
import {
  EuiFlexGrid,
  EuiFlexItem,
  EuiPanel,
  EuiTitle,
  EuiHealth,
  EuiSpacer,
  EuiDescriptionList,
  EuiEmptyPrompt,
  EuiCallOut,
  EuiText,
} from "@elastic/eui";
import { getPipelineStatus } from "../api";
import { usePolling } from "../lib/usePolling";
import { fmtAgo, fmtTime } from "../lib/format";
import PanelTitle from "../components/PanelTitle";

// A detector's state as the heartbeat reports it, unless it has gone quiet.
function detectorHealth(c) {
  if (c.stale) return { color: "danger", text: `silent — last heartbeat ${fmtAgo(c.last_heartbeat)}` };
  if (c.state === "warming_up")
    return { color: "warning", text: `warming up (${c.windows_buffered}/${c.min_windows} windows)` };
  if (c.state === "starting") return { color: "primary", text: "starting" };
  return { color: "success", text: "running" };
}

function Card({ title, health, items }) {
  return (
    <EuiPanel hasBorder>
      <EuiTitle size="xs">
        <h2>{title}</h2>
      </EuiTitle>
      <EuiSpacer size="xs" />
      <EuiHealth color={health.color}>{health.text}</EuiHealth>
      {items?.length > 0 && (
        <>
          <EuiSpacer size="s" />
          <EuiDescriptionList type="column" compressed listItems={items} />
        </>
      )}
    </EuiPanel>
  );
}

export default function Pipeline() {
  const [s, setS] = useState(null);
  const [error, setError] = useState(null);

  usePolling(async (isCurrent) => {
    try {
      const d = await getPipelineStatus();
      if (!isCurrent()) return;
      setS(d);
      setError(null);
    } catch (e) {
      if (isCurrent()) setError(String(e.message ?? e));
    }
  }, 15000);

  if (error) return <EuiCallOut title={`Status unavailable: ${error}`} color="danger" iconType="warning" />;
  if (!s) return null;

  const os = s.opensearch;
  const wz = s.wazuh_api;
  const ex = s.explainer;

  return (
    <>
      <EuiFlexGrid columns={3}>
        <EuiFlexItem>
          <Card
            title="OpenSearch"
            health={{
              color: os.ok ? (os.status === "green" ? "success" : "warning") : "danger",
              text: os.ok ? `cluster ${os.status}` : "unreachable",
            }}
            items={os.ok ? [{ title: "Cluster", description: os.cluster ?? "—" }] : [{ title: "Error", description: os.detail }]}
          />
        </EuiFlexItem>
        <EuiFlexItem>
          <Card
            title="Wazuh manager API"
            health={{ color: wz.ok ? "success" : "danger", text: wz.ok ? "reachable" : "unreachable" }}
            items={
              wz.ok
                ? [{ title: "Agents active", description: `${wz.agents_active} of ${wz.agents_total}` }]
                : [{ title: "Error", description: wz.detail }]
            }
          />
        </EuiFlexItem>
        <EuiFlexItem>
          <Card
            title="Explainer"
            health={{ color: ex.ok ? "success" : "warning", text: ex.ok ? "available" : "not available" }}
            items={[
              { title: "Provider", description: ex.provider },
              ...(ex.model ? [{ title: "Model", description: ex.model }] : []),
              { title: "Status", description: ex.detail },
            ]}
          />
        </EuiFlexItem>
      </EuiFlexGrid>

      <EuiSpacer />
      <PanelTitle
        title="Detectors"
        info="Each detection consumer reports a heartbeat every scoring cycle (60s). A detector that misses three counts as silent — no AI detections from it then means it isn't running, not that nothing happened."
      />
      <EuiSpacer size="s" />
      {s.consumers.length === 0 ? (
        <EuiEmptyPrompt
          iconType="pipelineApp"
          titleSize="xs"
          title={<h3>No detector has reported yet</h3>}
          body={
            <p>
              Consumers write a heartbeat once started (<code>ai-stack/start_all.sh</code>).
              Consumers from before this dashboard version don&rsquo;t report.
            </p>
          }
        />
      ) : (
        <EuiFlexGrid columns={2}>
          {s.consumers.map((c) => (
            <EuiFlexItem key={c.consumer}>
              <Card
                title={`${c.consumer}${c.lane ? ` · ${c.lane} lane` : ""}`}
                health={detectorHealth(c)}
                items={[
                  { title: "Model", description: c.model ?? "—" },
                  { title: "Last result", description: c.last_result ?? "—" },
                  { title: "Windows buffered", description: `${c.windows_buffered} (scores from ${c.min_windows})` },
                  { title: "Events seen", description: String(c.events_seen ?? "—") },
                  { title: "Detections written", description: String(c.detections_written ?? "—") },
                  { title: "Last event", description: fmtAgo(c.last_event_at) },
                  { title: "Last heartbeat", description: fmtAgo(c.last_heartbeat) },
                  { title: "Started", description: fmtTime(c.started_at) },
                  { title: "Kafka", description: `${c.kafka_bootstrap} · ${c.topic}` },
                  { title: "Writing to", description: c.index ?? "—" },
                ]}
              />
            </EuiFlexItem>
          ))}
        </EuiFlexGrid>
      )}

      <EuiSpacer />
      <Card
        title="Data flow"
        health={{
          color: s.data.last_rule_alert ? "success" : "subdued",
          text: s.data.last_rule_alert ? "alerts arriving" : "no alerts indexed yet",
        }}
        items={[
          { title: "Last rule alert", description: fmtAgo(s.data.last_rule_alert) },
          { title: "Last AI detection", description: fmtAgo(s.data.last_ai_detection) },
        ]}
      />
      <EuiSpacer size="s" />
      <EuiText size="xs" color="subdued">
        <p>Checked {fmtTime(s.checked_at)}.</p>
      </EuiText>
    </>
  );
}
