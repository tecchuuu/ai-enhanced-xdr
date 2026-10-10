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
| web | nginx/apache access logs | request rate, URL diversity, 4xx ratio, POST ratio | fuzzing, injection, login brute force | online + validated 2026-09-09 (R11): content discovery + path traversal caught, real off-host IP |
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

**Implemented (2026-09-09).** The slot is now a registry: `ai-stack/pipeline/models/`
(`isolation_forest.py`, `autoencoder.py`), one interface `fit_score(X, contamination)`,
selected by `DETECTOR_MODEL` in `.env`. Swapping is a config change, not a code edit.
Autoencoder built (PyTorch, device-aware CPU/GPU) and compared head-to-head with IF (results
log R12: comparable, autoencoder slightly broader on the low-and-slow phase). **On SIAM:** Morpheus's `dfencoder` becomes a third
registry entry occupying the same slot — the CPU autoencoder is the portable proof of the
same method. Bigger data (below) is where the autoencoder is expected to pull ahead.

## 2b. Data — sourced independently (NOT supplied by SIAM)
**Correction (2026-10-10):** SIAM does not supply datasets — they are sourced online
independently. The per-lane requirement is unchanged, and the coherent-slice rule still
holds (never mix lanes):
- **Auth lane** → SIAM Linux auth logs (multi-host, multi-user, real IPs) directly
  retire the single-host / single-IP / no-success-baseline limits in results-log §5.3.
- **Network lane** → **the BlueField-3 DPU was never provisioned** (failure log Entry 27),
  so this lane runs a software sensor: Suricata or Zeek on the host, emitting the same
  EVE-JSON records. Public Zeek/Suricata captures fit that shape directly; CICIDS2017 is
  an optional external benchmark, not the plan (different schema).

## 3. LLM is a READER, not a pipeline stage — LIVE on the H100
The LLM consumes existing `ai-detections-*` docs and writes a 2-sentence analyst
explanation back onto the doc (`ai.explanation`). The flyout displays it. It
attaches on top; it never sits in the detection path (a slow/dead LLM must never
delay detection — same reasoning as Kafka decoupling rules from AI).

**Status: live on `ollama` (gemma3:12b, H100). `mock` remains the no-model fallback.** `dashboard/explainer.py` +
`POST /api/explain` (one-shot, written onto the doc) + `POST /api/explain/chat`
(follow-up Q&A, thread held client-side) + an "Analyst assistant" panel in the
flyout: explain → then ask questions about that detection. Provider is one env
var, `EXPLAINER_PROVIDER`:
- `mock` (default) — deterministic template from the detection's own fields.
  Works now; this is the honest "explanation layer done, model deferred" state.
- `ollama` — local model via `http://localhost:11434`. **LIVE since 2026-10-10
  (R15):** gemma3:12b on the SIAM H100, 0.8-1.2 s per explanation warm, nothing
  leaves the box. Requires `OLLAMA_CONTEXT_LENGTH=4096` on the Ollama service —
  its 131072 default crashes model load (failure log Entry 28).
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
  **Blocked as of 2026-08-28:** the VM adapter is NAT, so the host cannot reach it.
  Switch to bridged (or add a port-forward) before attempting this.
- Producer needs docker group access — **done** (2026-08-28): `magi` is in the `docker` group, so plain `docker` works and the pipeline runs as the desktop user, not root.
- Console colors live in `dashboard/frontend/src/theme/palette.js`, one validated
  set per color mode. Do not add a hex anywhere else — dark is not a flip of light.
- Full design history: `docs/dashboard-plan.md`.
