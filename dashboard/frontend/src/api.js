import { loadSession } from "./lib/session";

// Same origin by default: the backend serves the built console, and the Vite
// dev server proxies /api. VITE_API_URL points elsewhere (then the backend's
// ALLOWED_ORIGINS must list the console's origin).
const API = import.meta.env.VITE_API_URL ?? "";

// The analyst name is percent-encoded: header values must be Latin-1, and a
// name in Thai isn't. The backend decodes it.
function sessionHeaders() {
  const { apiKey, analyst } = loadSession();
  return {
    ...(apiKey ? { "X-API-Key": apiKey } : {}),
    ...(analyst ? { "X-Analyst": encodeURIComponent(analyst) } : {}),
  };
}

async function request(path, init = {}) {
  const res = await fetch(`${API}${path}`, {
    ...init,
    headers: { ...init.headers, ...sessionHeaders() },
  });
  const body = await res.json().catch(() => ({}));
  if (res.status === 401) window.dispatchEvent(new Event("aixdr:unauthorized"));
  if (!res.ok) throw new Error(body.detail ?? `${path.split("?")[0]} -> HTTP ${res.status}`);
  return body;
}

const fetchJson = (path) => request(path);

// {a: 1, b: undefined} -> "?a=1"; empty values are left out
function query(params = {}) {
  const p = new URLSearchParams();
  for (const [k, v] of Object.entries(params)) {
    if (v != null && v !== "") p.set(k, v);
  }
  const s = p.toString();
  return s ? `?${s}` : "";
}

const postJson = (path, payload) =>
  request(path, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify(payload),
  });

export const getHealth = () => fetchJson("/api/health");

// scoped endpoints take {start, end, agent} (see lib/scope.js) plus their own
// params, in the API's snake_case: limit, offset, min_level, q, triage
// ("new,investigating"), sort ("timestamp" | "level"), order
export const getRuleAlerts = (params) => fetchJson(`/api/alerts/rule${query(params)}`);
export const getAiAlerts = (params) => fetchJson(`/api/alerts/ai${query(params)}`);
export const getBreakdown = (params) => fetchJson(`/api/alerts/breakdown${query(params)}`);
export const getQueue = (params) => fetchJson(`/api/queue${query(params)}`);
export const getCombined = (params) => fetchJson(`/api/alerts/combined${query(params)}`);
export const getHistogram = (params) => fetchJson(`/api/alerts/histogram${query(params)}`);
export const getTopSrcIps = (params) => fetchJson(`/api/alerts/top_srcips${query(params)}`);
export const getMetrics = (params) => fetchJson(`/api/metrics${query(params)}`);

export const getAlert = (alertId) => fetchJson(`/api/alerts/one${query({ alert_id: alertId })}`);
export const getAlertDoc = (alertId) => fetchJson(`/api/alerts/doc${query({ alert_id: alertId })}`);
export const getRelated = (alertId) =>
  fetchJson(`/api/alerts/related${query({ alert_id: alertId })}`);
export const getIpEntity = (ip) => fetchJson(`/api/entities/ip/${encodeURIComponent(ip)}`);

export const getPipelineStatus = () => fetchJson("/api/pipeline/status");
export const getAgents = () => fetchJson("/api/agents");
export const getResponseLog = (limit = 100) => fetchJson(`/api/response/log?limit=${limit}`);
export const getBlockedIps = () => fetchJson("/api/response/blocked");

export function setTriage({
  alertId,
  status,
  assignee,
  note,
  falsePositive,
  alertRef,
  alertTimestamp,
  alertSource,
  alertAgent,
}) {
  return postJson("/api/triage", {
    alert_id: alertId,
    status,
    assignee,
    note,
    false_positive: falsePositive,
    alert_ref: alertRef,
    alert_timestamp: alertTimestamp,
    alert_source: alertSource,
    alert_agent: alertAgent,
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
