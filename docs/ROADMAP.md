# Roadmap — read this when resources arrive

Three rules, in priority order:

## 1. More attack types = more input views, NOT a smarter model
The model is not the bottleneck; features are. The auth detector only sees
srcip-carrying auth events (windowed into event_count / distinct_users /
events_per_user / hour). To cover a new attack type, clone
`ai-stack/pipeline/detection_consumer.py` with a feature set for that domain:

| Detector | Feed | Features | Catches | Status |
|---|---|---|---|---|
| auth | sshd/PAM | events/user, distinct users | brute force, spraying | exists, evaluated |
| web | nginx/apache access logs | request rate, URL diversity, 4xx ratio, POST ratio | fuzzing, injection, login brute force | `web_detection_consumer.py` written, **not yet run** against a live stack |
| network | conn/firewall logs | distinct dst ports, conn rate/src | port scans, sweeps | not started |
| host | FIM/syscheck (already running) | file changes/min, new bins, sudo | persistence, priv-esc | not started |

Each writes to the same `ai-detections-*` schema with its own `ai.category` and
rule id (auth = 100001, web = 100002). Dashboard/backend need zero changes —
they already render category, severity, top_srcips.

**Web detector — to bring online:** stand up nginx on the monitored host, feed
`/var/log/nginx/access.log` to Wazuh via a `<localfile>` block, then run
`web_detection_consumer.py` alongside the auth consumer (its own Kafka consumer
group, so both see every event). Attack it from another host with `ffuf`
(content discovery), `hydra http-post-form` (login brute force), `sqlmap`
(injection). Setup detail is in the module docstring.

## 2. GPU arrives → swap ONLY the inference slot
Isolation Forest → autoencoder (Morpheus DFP's approach: learn to reconstruct
"normal", flag high reconstruction error). Same contract: Kafka in, detection
docs out, same index schema. Nothing upstream or downstream changes — that's
the "swap not rewrite" claim in the README; keep it true.

## 3. RAM arrives → LLM is a READER, not a pipeline stage
The LLM consumes existing `ai-detections-*` docs and writes a 2-sentence analyst
explanation back onto the doc (`ai.explanation`). The flyout displays it. It
attaches on top; it never sits in the detection path (a slow/dead LLM must never
delay detection — same reasoning as Kafka decoupling rules from AI).

**Status: built, on the `mock` provider.** `dashboard/explainer.py` +
`POST /api/explain` (one-shot, written onto the doc) + `POST /api/explain/chat`
(follow-up Q&A, thread held client-side) + an "Analyst assistant" panel in the
flyout: explain → then ask questions about that detection. Provider is one env
var, `EXPLAINER_PROVIDER`:
- `mock` (default) — deterministic template from the detection's own fields.
  Works now; this is the honest "explanation layer done, model deferred" state.
- `ollama` — local model via `http://localhost:11434` (llama3.2:3b etc.). The
  RAM-arrives target. Untested.
- `anthropic` — hosted Claude API (`pip install anthropic`, `ANTHROPIC_API_KEY`).
  Sends detection fields off-box — a data-egress call to make explicitly in the
  report. Untested.
Swapping providers is one env var; the prompt and the writeback are shared, so
"the explainer is model-agnostic" is demonstrable the same way the inference
slot is.

## Also remember
- Detections written before Aug 2026 lack category/top_srcips (pre-enrichment).
- Mock traffic from 127.0.0.1 is never blockable (loopback guard) — attack from
  another host (VM LAN: attack ssh on this machine from the host) to demo Block IP.
- Producer needs docker group access (`sudo usermod -aG docker $USER`, re-login).
- Full design history: `docs/dashboard-plan.md`.
