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
| **Category breakdown** — AI detections by heuristic category | `GET /api/alerts/by_category` | `CategoryBreakdown` component (Overview + Metrics) |
| **Blocked-IP management** — current block set + unblock | `GET /api/response/blocked`, `POST /api/response/unblock-ip` | `BlockedIps` component on the Response log page |

## Contracts

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
  "created_at": "…",
  "updated_at": "…"
}
```
`alert_timestamp` / `alert_source` are copied from the alert at write time so
`/api/metrics` can compute FP rate and MTTR without joining back to the alert
indices.

### `/api/metrics`
- `rule_alerts` / `ai_detections` — counts in the window (rules: level ≥ 10).
- `overlap_minutes` — bucket both streams into 1-minute bins:
  - `ai_only` = minutes the model fired and no rule did → **this is the headline
    Claim B number, rendered live.**
  - `both` = corroboration, `rule_only` = rules alone.
- `false_positive_rate` = FP-flagged AI detections ÷ AI detections in window.
- `mttr_seconds` = mean(`updated_at` − `alert_timestamp`) over triage records in
  `resolved` / `false_positive`.

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
   command and *always* records the intent so the console's block view stays
   consistent — but a persistent drop may need `iptables -D` on the agent or a
   custom delete AR. This is a Wazuh constraint, not a design gap.
2. **`ai.category.keyword`** — the category aggregation assumes dynamic mapping
   on `ai-detections-*`. If a later index template maps `ai.category` as a bare
   keyword, change the agg field in `_category_agg()`. Falls back to empty on
   error, so nothing breaks.
3. **Pre-August detections** lack `category` / `top_srcips` (pre-enrichment) —
   the breakdown chart only reflects newer detections.
4. **MTTR / FP rate are only meaningful once analysts work the queue** — with an
   empty `ai-alert-triage` index they read 0 / "—".

## To verify against a live stack

- [ ] `ai-alert-triage` index auto-creates on first `POST /api/triage` (dynamic
      mapping) — or add an explicit mapping if `note` full-text search is wanted.
- [ ] Triage save round-trips: set status in the flyout → column + badge update
      after the 15s refresh (or immediately via the `onRefresh` path).
- [ ] `/api/metrics` overlap math against a known scenario (fast brute force =
      high `both`; slow brute force = high `ai_only`).
- [ ] `by_category` returns buckets (confirms the `.keyword` field assumption).
- [ ] Block an IP from another host → it appears in **Currently blocked** →
      unblock → it leaves the list and a `unblock-ip` row lands in the audit log.
- [ ] `POST /api/explain` on a real detection → text comes back, `ai.explanation`
      is persisted (re-open the flyout, it's still there), other `ai.*` fields
      intact. Then ask a follow-up in the panel → `/api/explain/chat` replies.
      Mock provider works offline; try `ollama` once a model is pulled, or
      `EXPLAINER_PROVIDER=anthropic` with a key.
- [ ] Frontend builds: `cd dashboard/frontend && npm install && npm run build`
      (not run here — no Node on the build machine).

## Not built (future work — one line each in ROADMAP / บทที่ 5)

Geo map, bulk triage actions, host isolation / disable-user, saved views,
full case management, threat-intel enrichment, analyst-activity reporting.
