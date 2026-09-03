const API = import.meta.env.VITE_API_URL ?? "http://localhost:8000";

async function fetchJson(path) {
  const res = await fetch(`${API}${path}`);
  if (!res.ok) throw new Error(`${path} -> HTTP ${res.status}`);
  return res.json();
}

async function postJson(path, payload) {
  const res = await fetch(`${API}${path}`, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify(payload),
  });
  const body = await res.json().catch(() => ({}));
  if (!res.ok) throw new Error(body.detail ?? `HTTP ${res.status}`);
  return body;
}

export const getHealth = () => fetchJson("/api/health");
export const getStats = () => fetchJson("/api/stats");
export const getRuleAlerts = (limit = 100, minLevel = 0) =>
  fetchJson(`/api/alerts/rule?limit=${limit}&min_level=${minLevel}`);
export const getAiAlerts = (limit = 100) => fetchJson(`/api/alerts/ai?limit=${limit}`);
export const getCombined = (limit = 200) => fetchJson(`/api/alerts/combined?limit=${limit}`);
export const getHistogram = (hours = 24, interval = "30m") =>
  fetchJson(`/api/alerts/histogram?hours=${hours}&interval=${interval}`);
export const getTopSrcIps = (hours = 24) => fetchJson(`/api/alerts/top_srcips?hours=${hours}`);
export const getByCategory = (hours = 168) =>
  fetchJson(`/api/alerts/by_category?hours=${hours}`);
export const getAgents = () => fetchJson("/api/agents");
export const getResponseLog = (limit = 100) => fetchJson(`/api/response/log?limit=${limit}`);
export const getBlockedIps = () => fetchJson("/api/response/blocked");
export const getMetrics = (hours = 168) => fetchJson(`/api/metrics?hours=${hours}`);
export const getTriage = (limit = 500) => fetchJson(`/api/triage?limit=${limit}`);

export function setTriage({ alertId, status, assignee, note, falsePositive, alertRef, alertTimestamp, alertSource }) {
  return postJson("/api/triage", {
    alert_id: alertId,
    status,
    assignee,
    note,
    false_positive: falsePositive,
    alert_ref: alertRef,
    alert_timestamp: alertTimestamp,
    alert_source: alertSource,
  });
}

export function blockIp({ agentId, srcip, alertRef, reason }) {
  return postJson("/api/response/block-ip", {
    agent_id: agentId,
    srcip,
    alert_ref: alertRef,
    reason,
  });
}

export function unblockIp({ agentId, srcip, reason }) {
  return postJson("/api/response/unblock-ip", { agent_id: agentId, srcip, reason });
}

export function explainAlert(alertId, provider) {
  return postJson("/api/explain", { alert_id: alertId, provider });
}

export function explainChat(alertId, messages, provider) {
  return postJson("/api/explain/chat", { alert_id: alertId, messages, provider });
}
