# XDR Dashboard v2 — Plan

Goal: replace the static `dashboard/dashboard.html` with a Wazuh-look-alike SOC console
that adds the AI layer on top. Familiarity first — a SOC analyst who knows Wazuh should
feel at home immediately; the AI detections and response actions are the only new things
they have to learn.

---

## 1. The key insight: use Wazuh's own UI library

Wazuh's dashboard is a plugin inside **OpenSearch Dashboards** (a Kibana fork), and both
are built on the **EUI** React component library (`@elastic/eui`; OpenSearch's fork is
`@opensearch-project/oui`). If we build a small React app using EUI, we get the exact
Wazuh look for free — same tables, same flyouts, same badges, same stat panels — instead
of hand-copying CSS. This is the strongest possible answer to "psychologically similar."

## 2. Recommended tech stack

| Layer      | Choice                                   | Why |
|------------|------------------------------------------|-----|
| Frontend   | **React 18 + Vite + @elastic/eui**       | EUI = the actual Wazuh component library. Vite = zero-config dev server + build. |
| Charts     | EUI's `@elastic/charts`                  | Same charting library Wazuh uses (the histograms/pies you see in Security Events). |
| Backend    | **Keep FastAPI**, extend it              | Already works; just add endpoints. Add `httpx` for calling the Wazuh API. |
| Data       | OpenSearch (existing) + one new index    | `ai-responses-*` — audit log of response actions taken from the dashboard. |
| Actions    | **Wazuh API** (port 55000) + Active Response | Block IP via Wazuh's built-in `firewall-drop`; agent status via `/agents`. Real SOC actions, not simulated. |

Fallback if React feels like too much for the course timeline: keep vanilla JS but adopt
EUI's CSS variables/design tokens manually. ~70% of the look for ~40% of the effort, but
tables and flyouts get painful. Recommendation stands: React + EUI.

## 3. Layout — mirror Wazuh's Security Events page

```
┌────────────────────────────────────────────────────────────────┐
│ Top bar: AI-XDR logo · agent selector · time range picker      │
├──────────┬─────────────────────────────────────────────────────┤
│ Side nav │  ┌ Stat panels row ───────────────────────────────┐ │
│          │  │ Total alerts │ Rule alerts │ AI detections │    │ │
│ Overview │  │ Model-only catches │ Blocked IPs │ Agents up    │ │
│ Security │  └────────────────────────────────────────────────┘ │
│  Events  │  ┌ Charts row ────────────────────────────────────┐ │
│ AI       │  │ Alerts-over-time histogram (rule vs AI stacked)│ │
│  Detect. │  │ Threat category pie · Top source IPs bar       │ │
│ Response │  └────────────────────────────────────────────────┘ │
│  Log     │  ┌ Alerts table (EuiDataGrid) ────────────────────┐ │
│ Agents   │  │ time · agent · rule id · severity · category · │ │
│          │  │ description · source(rule/AI) · srcip · actions│ │
│          │  │  → row click opens detail flyout (like Wazuh)  │ │
└──────────┴──└────────────────────────────────────────────────┘─┘
```

Detail flyout (right-side panel, exactly like Wazuh's alert inspector):
- Rule alert → rule metadata, full JSON, MITRE tags
- AI detection → anomaly score gauge, window features (event count, distinct users,
  events/user), "why it fired" explanation, and later the LLM explanation text
- Both → **[Block IP]** button with confirmation modal if a `srcip` is present

## 4. Features and phases

### Phase 1 — Skeleton + Security Events clone (the familiarity payload)
- Vite + React + EUI scaffold in `dashboard/frontend/`
- Side nav, top bar, dark theme (EUI ships Wazuh's dark palette)
- Alerts table over the existing `/api/alerts/combined`, with a `source` badge
  column: `rule` (orange) vs `AI` (teal) — keeps your current color language
- Stat panels row from `/api/stats`

### Phase 2 — Alert detail flyout + charts
- Flyout with the full document, severity badge, copy-as-JSON
- Alerts-over-time stacked histogram (rule vs AI) — the signature Wazuh visual
- New endpoint: `GET /api/alerts/histogram` (date_histogram agg, split by source)

### Phase 3 — Threat category
- **Rule alerts**: Wazuh already tags alerts with `rule.mitre.tactic` / `technique`
  and `rule.groups` — surface them, don't invent anything. Category column + pie chart.
- **AI detections**: the model only says "anomalous," so add a lightweight
  post-classification step in `detection_consumer.py` based on window features:
  - high `events_per_user`, few users → `brute_force` (T1110.001)
  - many `distinct_users`, low events each → `password_spraying` (T1110.003)
  - off-hours (`hour` outside baseline) + moderate volume → `suspicious_timing`
  - otherwise → `unclassified_anomaly`
  Written into the detection doc as `ai.category` + `ai.mitre`. This is a nice
  report talking point: unsupervised detection + heuristic labeling = analyst triage aid.

### Phase 4 — Pipeline fix: capture source IPs (prerequisite for blocking)
`detection_consumer.py` currently discards IPs — a detection can't be blocked if it
doesn't say who to block. Changes:
- Track `ips: Counter` per window alongside `users`
- Write `ai.top_srcips: [{ip, count}, ...]` (top 5) into each detection doc
- While here: scale `rule.level` by anomaly score instead of hardcoding 10
  (score < −0.60 → 12, < −0.50 → 10, else 7) so severity filtering means something

### Phase 5 — Response actions (Block IP / monitor)
- Backend gets a Wazuh API client (JWT auth against `https://localhost:55000`,
  user `wazuh-wui`, creds from `.env` — **stop hardcoding `SecretPassword`**, move
  the OpenSearch creds to `.env` at the same time)
- `POST /api/response/block-ip` → Wazuh Active Response `PUT /active-response`
  with command `!firewall-drop` against the target agent; body carries the srcip.
  Wazuh's agent-side AR script does the actual iptables drop — you're using the
  real mechanism SOCs use, not a simulation.
- Optional `timeout` arg = auto-unblock after N seconds (AR supports this) —
  safer default for a demo box (e.g. 600s).
- Every action logged to `ai-responses-*`: who/what/when/why (alert id), shown on
  the **Response Log** page. Auditability = another report talking point.
- **Agents page**: `GET /api/agents` proxying Wazuh API `/agents` — status
  (active/disconnected), OS, IP, last keep-alive. Wazuh-style table with green/red
  status badges.

### Phase 6 (stretch, ties into your stated roadmap)
- LLM explanation panel in the AI-detection flyout (your local LLM writes a
  2-sentence analyst summary of the window features)
- Auto-response toggle: AI detection ≥ level 12 with a top srcip → auto-block with
  timeout, logged. Off by default; demo the toggle live.

## 5. Backend endpoint summary (target state)

```
GET  /api/health
GET  /api/stats                  (extend: blocked count, agent count)
GET  /api/alerts/rule
GET  /api/alerts/ai
GET  /api/alerts/combined
GET  /api/alerts/histogram       NEW  date_histogram split rule/AI
GET  /api/alerts/categories      NEW  terms agg for the pie
GET  /api/agents                 NEW  Wazuh API proxy
POST /api/response/block-ip      NEW  Active Response trigger + audit write
GET  /api/response/log           NEW  reads ai-responses-*
```

## 6. Repo layout after the change

```
dashboard/
  backend/
    main.py            (moved, extended)
    wazuh_api.py       NEW — JWT client for the Wazuh manager API
    .env.example       NEW — WAZUH_API_URL, WAZUH_API_USER/PASS, OS_USER/PASS
  frontend/
    index.html, vite.config.js, package.json
    src/
      App.jsx, api.js
      pages/  Overview.jsx  SecurityEvents.jsx  AiDetections.jsx
              ResponseLog.jsx  Agents.jsx
      components/  AlertsTable.jsx  AlertFlyout.jsx  StatPanels.jsx
                   BlockIpModal.jsx  SourceBadge.jsx
  dashboard.html       (keep as the "detection split" demo view — it's a good
                        side-by-side visual for the report; link it from the nav)
```

## 7. Order of work & rough effort

1. Phase 1 skeleton — ~1 session (most of it is `npm create vite` + EUI boilerplate)
2. Phase 2 flyout + histogram — ~1 session
3. Phase 4 pipeline IP capture — small, do it early (data needs time to accumulate!)
4. Phase 3 categories — ~half a session
5. Phase 5 block IP + agents + response log — ~1–2 sessions (Wazuh API auth is the fiddly part)
6. Phase 6 stretch goals — as time allows

Note the ordering: **do Phase 4 (IP capture) right after the skeleton**, because only
detections written *after* that change will be blockable — you want realistic data
accumulated before the demo.

## 8. Security hygiene (worth a line in the report)

- All credentials to `.env` (git-ignored); `.env.example` committed
- CORS locked to the frontend origin instead of `*`
- Block-IP endpoint validates the IP (no blocking RFC1918 gateway / your own host),
  requires a confirm step in the UI, and every action is audit-logged
