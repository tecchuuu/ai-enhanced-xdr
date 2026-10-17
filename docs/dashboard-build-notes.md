# Dashboard build notes — SOC console additions

*Added 2026-08-27. Companion to `dashboard-plan.md` (design history). This records
what was added on top of the original console, the contracts involved, and what
still needs verifying against a live stack.*

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

## Contracts

### Scope (`start`, `end`, `agent`)
The header's date picker holds date-math strings (`now-24h`); the client
resolves them to ISO at every fetch (`lib/scope.js`) so a relative range keeps
sliding. Feeds without `start`/`end` are all-time (the legacy split view relies
on this); charts and metrics default to the last 24h / 7d. `agent` is matched
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
- [x] Frontend builds: `npm ci && npm run build` passes (Node 24, Vite 8),
      `oxlint` clean apart from the fast-refresh notices in `badges.jsx` /
      `ThemeProvider.jsx`.

## Not built (future work — one line each in ROADMAP / บทที่ 5)

Geo map, bulk triage actions, host isolation / disable-user, saved views,
full case management, threat-intel enrichment, analyst-activity reporting.
