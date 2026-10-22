# Dashboard build notes — SOC console additions

*Added 2026-08-27. Companion to `dashboard-plan.md` (design history). This records
what was added on top of the original console, the contracts involved, and what
still needs verifying against a live stack.*

## Revision after a cybersecurity lecturer's review (2026-10-22)

A lecturer who reviewed the console from the screen alone (no pipeline
background) found the wording unclear, the severity colours incomplete, and the
two alert pages inconsistent. All changes are presentation; no detector,
pipeline or stored data changed. See failure_log Entry 43.

| Was | Now | Why |
|---|---|---|
| Security events | **Wazuh alerts** | an *event* is any log line; these are alerts raised by rules (read as "Windows events") |
| Detection split + Metrics (two pages) | **Rules vs AI** (one page: tiles, then the minute-by-minute view) | Metrics was six tiles on an empty page, three of them repeated |
| "Minutes AI-only (rules silent)", "missed by rules" | **Flagged only by AI** (counted in AI detections, not minutes) | the console has no ground truth: rule/AI disagreement is not proof the rules missed anything |
| AI FP rate = false positives / *all* AI detections (0.0% before any review) | false positives / **reviewed** AI detections; "—" until one is reviewed (`ai_reviewed`, `false_positive_rate: null`) | unreviewed detections aren't known to be right |
| Severity 12+ critical, 10+ high; only critical coloured | Wazuh's dashboard bands: **15+ critical, 12–14 high, 7–11 medium, 0–6 low**, coloured red / orange / yellow / slate | same name for the same alert in both UIs; the SOC colour convention |
| Source colours orange (rule) / green (AI) | blue (Wazuh) / purple (AI) | off the severity ramp, so a Wazuh row never reads as "high" |
| Anomaly score as stored (−0.71, lower = worse) | shown flipped (**0.71, higher = more unusual**), each model on its own scale | the direction analysts expect; the assistant's prompt uses the same numbers |
| "window", "buffer", "heartbeat", rule id 100001 in tables | "minute", "collected", "check-in"; rule id only for Wazuh rules, in the detail panel | code words on screen |
| Warning banner on every page per silent detector | one detector status in the header | a standby detector put a warning on every screen |
| Agent `001` in the response log | agent name (`agent_name`, cached id→name from the Wazuh API) | |
| AI page only had a chart | **Alerts by rule** chart on Wazuh alerts too; integer axes, counts on bars, height by bar count | the two alert pages read the same way |

## What was added

Four capability groups, all serving the "does the AI add value, and can an
analyst act on it" story — not decoration.

| Feature | Backend | Frontend |
|---|---|---|
| **Alert triage** — status / assignee / note / false-positive per alert | `ai-alert-triage` index, `GET`/`POST /api/triage` | triage panel in `AlertFlyout`, triage column + filter in `AlertsTable` |
| **Metrics** — live rule-vs-AI comparison, FP rate, MTTR | `GET /api/metrics` | new **Metrics** page |
| **Category breakdown** — AI detections by heuristic category | none — counted in the browser from the loaded detections, so it always matches the table | chart on the **AI detections** page |
| **Blocked-IP management** — current block set + unblock | `GET /api/response/blocked`, `POST /api/response/unblock-ip` | `BlockedIps` component on the Response log page |
| **Scope** — one time range + agent for the console | `start` / `end` / `agent` on every list and chart endpoint | date picker + agent selector in the page header (Overview, Security events, AI detections, Metrics) |
| **Search** — IP, user, rule id or text across all fields | `q` on `/api/alerts/rule` and `/api/alerts/ai` | search field on both feeds |
| **IP pivot** — everything on one source address, all time | `GET /api/entities/ip/{ip}` | `IpFlyout`, opened from any IP link or the top-IPs chart |
| **Related events** — rule alerts around one alert | `GET /api/alerts/related` | panel in `AlertFlyout` |
| **Raw document** — the stored `_source` behind an alert | `GET /api/alerts/doc` | accordion in `AlertFlyout` |
| **Why it fired** — window features vs the fit's baseline, score vs cutoff | consumers write `ai.features` / `ai.baseline` / `ai.threshold` / `ai.windows_scored` (`ai-stack/pipeline/consumer_common.py`) | `WhyItFired` panel in the AI alert flyout; the explainer prompt uses the same fields |
| **Pipeline health** — is each part alive | consumers heartbeat into `ai-pipeline-status`; `GET /api/pipeline/status` | **Pipeline** page; detector status in the header (was `PipelineNotice` banners until 2026-10-22) |
| **Detection split** — rule vs AI, minute by minute | `/api/alerts/combined` (scoped) | **Detection split** page (replaces `dashboard.html`) |
| **Model** — which inference-slot occupant flagged it | `ai.model` (always written); `ai_by_model` in `/api/metrics` | Model column on AI detections; by-model line on Metrics |
| **Access** — optional shared key, analyst attribution | `DASHBOARD_API_KEY` → `X-API-Key` on every `/api` call but `/api/health`; `X-Analyst` → `initiated_by` / `updated_by`; CORS limited to `ALLOWED_ORIGINS` | `SessionModal` (asks once per browser), analyst name in the header, **By** column in the response log |
| **Block guardrails** — refuse unsafe blocks, show existing ones | `_block_refusal()`; `blocked` on every alert from the feeds | lock icon on blocked IPs, "source blocked" badge and footer in the alert flyout |
| **Links** — every view has a URL | `GET /api/alerts/one` (one alert, feed shape) | hash routes (`lib/route.js`): page, range, agent, open IP, open alert |
| **One port** — API serves the built console | `frontend/dist` mounted at `/` after the API routes | `npm run build`; `npm run dev` proxies `/api` (`vite.config.js`) |

## Contracts

### Scope (`start`, `end`, `agent`)
The header's date picker holds date-math strings (`now-24h`); the client
resolves them to ISO at every fetch (`lib/scope.js`) so a relative range keeps
sliding. Feeds without `start`/`end` are all-time; charts and metrics default
to the last 24h / 7d. `agent` is matched
with `match_phrase` on `agent.name`, which works for the keyword mapping in
`wazuh-alerts-*` and the analyzed text in the dynamically mapped
`ai-detections-*`. The histogram picks its bucket size from the range (≤ ~60
bars) and returns it as `interval`.

### Search (`q`)
`simple_query_string`, every term required, over `RULE_SEARCH_FIELDS` /
`AI_SEARCH_FIELDS` in `main.py` (includes `full_log`, users, IPs, URLs —
fields the table doesn't show). Runs on Enter. The table's own filter is now
only the triage-state buttons.

### Related events (`/api/alerts/related?alert_id=`)
Rule alerts at any level, 5 minutes either side of the alert (plus the AI
window's length), matched on the alert's source IPs (`ai.top_srcips` for a
detection, `data.srcip` for a rule alert); with no IP, on its agent. A rule
alert excludes itself. For an AI detection this is the closest thing to "the
events the model saw" — archives aren't indexed, but each decoded sshd/web
event raises a low-level rule alert.

### IP entity (`/api/entities/ip/{ip}`)
All-time, not scoped: rule alerts (`data.srcip`) and AI detections
(`ai.top_srcips.ip`), latest 200 of each with triage merged, totals,
first/last seen (min/max across both), targeted accounts (`data.srcuser` +
`data.dstuser`), agents, and the current block state from
`/api/response/blocked`.

### Alert identity
Every alert from `/api/alerts/*` now carries `id = "<source>:<opensearch _id>"`
(e.g. `ai:AbC123`, `rule:xYz789`). This is the triage key. Stable per document.

### Triage record (`ai-alert-triage`, doc `_id` = alert id)
```json
{
  "status": "new | investigating | resolved | false_positive",
  "assignee": "string | null",
  "note": "string | null",
  "false_positive": true,
  "alert_ref": "100001 — AI: anomalous auth …",
  "alert_timestamp": "2026-08-27T10:00:00+00:00",
  "alert_source": "ai | rule",
  "alert_agent": "ubuntu-vm",
  "created_at": "…",
  "updated_at": "…",
  "resolved_at": "… | null"
}
```
`alert_timestamp` / `alert_source` / `alert_agent` are copied from the alert at
write time so `/api/metrics` can compute FP rate and MTTR for the current scope
without joining back to the alert indices (under an agent filter, records
written before `alert_agent` existed are left out). `resolved_at` is set on the first move to `resolved` / `false_positive`
and kept on later edits, so touching a closed alert's note doesn't stretch MTTR;
it is cleared if the alert is reopened.

### `/api/metrics`
- `rule_alerts` / `ai_detections` — counts in the window (rules: level ≥ 10).
  `rule_alerts_all_levels` — rule volume at every level, for the alert-fatigue
  comparison (R8). The Overview stat tiles read this endpoint for their range, so
  Overview and Metrics show one definition of each number.
- `overlap_minutes` — bucket both streams into 1-minute bins:
  - `ai_only` = minutes the model fired and no rule did → **this is the headline
    Claim B number, rendered live.**
  - `both` = corroboration, `rule_only` = rules alone.
- `false_positive_rate` = FP-flagged AI detections ÷ AI detections in window.
- `mttr_seconds` = mean(`resolved_at` − `alert_timestamp`) over triage records in
  `resolved` / `false_positive` (records written before `resolved_at` existed
  fall back to `updated_at`).

### `/api/explain` + `/api/explain/chat` (analyst assistant)
`POST /api/explain {alert_id, provider?}` for an AI detection (`ai:<_id>`).
Fetches the detection from `ai-detections-*`, runs `dashboard/explainer.py`, and
writes the result back onto the document as `ai.explanation` (+ `ai.explained_by`,
`ai.explained_at`) with a partial `update` so the other `ai.*` fields survive.
The text is returned to the caller even if the writeback fails
(`persisted: false`).

`POST /api/explain/chat {alert_id, messages: [{role, content}], provider?}` —
follow-up Q&A. The **thread lives in the client** (the flyout), not the server
and not the detection doc; each call re-sends the running thread and the server
injects the detection as system context. Capped at 20 messages. Nothing is
persisted — closing the flyout discards the conversation (the one-shot
explanation stays because it's on the doc).

Provider = `EXPLAINER_PROVIDER` env var, overridable per call:
- `mock` (default) — deterministic template per `ai.category`, built from the
  detection's own numbers. No model, no network. The honest fallback state.
- `ollama` — local model, `OLLAMA_URL` / `OLLAMA_MODEL`. Untested.
- `anthropic` — hosted Claude, `pip install anthropic` + `ANTHROPIC_API_KEY`,
  `ANTHROPIC_MODEL` (default `claude-opus-5`; `claude-haiku-4-5` is plenty and
  cheaper). Sends detection fields (IPs, usernames) off-box. Untested.

The flyout shows the explanation for AI alerts with an "Explain this detection" /
"Regenerate" button.

### Detection evidence (`ai.*` on every new detection, both lanes)
Written by `consumer_common.fit_evidence()` from the fit that flagged the window:
- `features` — the window's own feature vector, as the model saw it.
- `baseline` — per feature, `{median, p95}` over the windows in the same fit the
  model did **not** flag: what normal looked like at scoring time.
- `threshold` — the least anomalous score flagged in that fit. The models flag
  a fixed share of windows (contamination 0.15), not a fixed score, so the
  cutoff moves with the rolling buffer; this is the real one, replacing the
  explainer's old `-0.5` guess (`FLAG_THRESHOLD` is now only the fallback for
  older detections).
- `windows_scored` — how many windows that fit saw.

`agent` is now the most common agent among the window's events (`id` + `name`)
instead of a hardcoded `ubuntu-vm`, and the index name is computed per write so
a consumer running past midnight rolls over to the new day's index.

### Pipeline status (`ai-pipeline-status`, doc `_id` = consumer name)
Each consumer overwrites its doc every scoring cycle (60s) and once at start:
`state` (`starting` / `warming_up` / `scoring`), `last_result`, `model`,
`lane`, `windows_buffered` / `min_windows`, `events_seen`,
`detections_written`, `last_event_at`, `last_heartbeat`, `started_at`,
`kafka_bootstrap`, `topic`, `index`, `score_every_sec`. A failed write is
logged, never raised. `/api/pipeline/status` marks a consumer `stale` after 3
missed cycles and adds OpenSearch cluster health, Wazuh API reachability +
active agents, newest rule alert / AI detection, and `explainer.status()`
(lists Ollama's models; never generates or calls the hosted API). The Overview
notice ignores a consumer silent for over a day — treated as deliberately
stopped (the web lane isn't always run); the Pipeline page still shows it.

### Access (`DASHBOARD_API_KEY`, `X-Analyst`)
Unset key = open API, as before. Set, every `/api` route except `/api/health`
needs `X-API-Key` (compared in constant time); `/api/health` reports
`auth_required` so the console knows to ask. A 401 still carries CORS headers.
The console keeps the key and the analyst name in this browser's localStorage
(`lib/session.js`) — a shared-secret gate for a lab on a shared VM, not user
accounts. The analyst name is percent-encoded in `X-Analyst` (header values
must be Latin-1; a Thai name isn't) and decoded server-side; it lands in the
audit doc's `initiated_by` and the triage doc's `updated_by`. CORS is only
needed for a console on another origin; same-origin (served by the API, or
through the Vite proxy) never triggers it.

### Block guardrails (`POST /api/response/block-ip`)
Refused (HTTP 400, audited as `refused`): loopback; unspecified / multicast /
link-local / reserved; anything in `BLOCK_ALLOWLIST` (IPs or CIDRs); the
address the console is used from (`X-Forwarded-For` first hop, else the
client — spoofing it can only refuse more); the target agent's own IP and the
manager's (agent `000`), from the Wazuh agent list. Already blocked on that
agent → 409. Feeds, the IP pivot and `/api/alerts/one` add `blocked` (the
current block entry, any agent) to each alert.

### Category vs MITRE
`category` is now *what kind of event*: a rule alert's most specific
`rule.groups` entry, or the AI heuristic. ATT&CK is separate on both sources:
`mitre` (technique) + `tactic` — Wazuh's `rule.mitre.tactic` for rules, a small
technique→tactic map (`AI_TACTICS`) for the AI heuristics' techniques.

## Known limitations (state these in the report)

1. **Unblock is best-effort.** Wazuh's manager API has no documented "undo
   firewall-drop". `POST /api/response/unblock-ip` attempts the paired delete
   command. If Wazuh does not accept it, the action is audited as `unconfirmed`
   and the IP stays in **Currently blocked**, flagged *unblock unconfirmed*, rather
   than being shown as unblocked — a persistent drop may need `iptables -D` on the
   agent or a custom delete AR. This is a Wazuh constraint, not a design gap.
2. **Pre-August detections** lack `category` / `top_srcips` (pre-enrichment) —
   the breakdown chart lists them as "no category".
3. **MTTR / FP rate are only meaningful once analysts work the queue** — with an
   empty `ai-alert-triage` index they read 0 / "—".

## To verify against a live stack

- [ ] `ai-alert-triage` index auto-creates on first `POST /api/triage` (dynamic
      mapping) — or add an explicit mapping if `note` full-text search is wanted.
- [ ] Triage save round-trips: set status in the flyout → column + badge update
      after the 15s refresh (or immediately via the `onRefresh` path).
- [ ] `/api/metrics` overlap math against a known scenario (fast brute force =
      high `both`; slow brute force = high `ai_only`).
- [ ] Block an IP from another host → it appears in **Currently blocked** →
      unblock → it leaves the list and a `unblock-ip` row lands in the audit log
      (or it stays, flagged *unblock unconfirmed*, if Wazuh rejects the delete).
- [ ] A web detection (rule 100002) opens with its URL fields and model name in
      the flyout, not "—".
- [ ] Type a triage note, wait past a 15s refresh without saving → the note is
      still there.
- [ ] `POST /api/explain` on a real detection → text comes back, `ai.explanation`
      is persisted (re-open the flyout, it's still there), other `ai.*` fields
      intact. Then ask a follow-up in the panel → `/api/explain/chat` replies.
      Mock provider works offline; try `ollama` once a model is pulled, or
      `EXPLAINER_PROVIDER=anthropic` with a key.
- [ ] Search hits on the real mappings: an IP in Security events (keyword
      `data.srcip`) and in AI detections (analyzed `ai.top_srcips.ip`), a
      username, a rule id. The test double can't check analyzers.
- [ ] Agent selector narrows both feeds and the Overview tiles.
- [ ] Related events on a real AI detection list the sshd alerts from its IP;
      the IP pivot's first/last seen and accounts look right for the attacker.
- [ ] `docker compose … up -d --build` (SETUP §5), then open `http://<vm>:8000`
      → the console (built inside the image) loads from the API's port; a
      copied alert link reopens the same alert.
- [ ] Set `DASHBOARD_API_KEY` → the console asks for it once; a browser without
      it gets nothing but `/api/health`.
- [ ] Blocking the VM's own IP, the manager's, or an allowlisted address is
      refused with a reason in the response log; blocking an IP twice → 409.
- [ ] Restart the detectors (`… restart auth-detector web-detector`) → the
      **Pipeline** page shows both `warming up`, then `running`; `… stop
      web-detector` → it turns `silent` within ~3 minutes and Overview says so.
- [ ] The next real AI detection has a **Why it fired** table with sensible
      medians, its real agent name, and an explanation (ollama) that quotes the
      recorded cutoff.
- [x] Frontend builds: `npm ci && npm run build` passes (Node 24, Vite 8),
      `oxlint` clean apart from the fast-refresh notices in `badges.jsx` /
      `ThemeProvider.jsx`.

## Not built (future work — one line each in ROADMAP / บทที่ 5)

Geo map, bulk triage actions, host isolation / disable-user, saved views,
full case management, threat-intel enrichment, analyst-activity reporting.
