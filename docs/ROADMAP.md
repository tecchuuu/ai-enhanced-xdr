# Roadmap — read this when resources arrive

Three rules, in priority order:

## 1. More attack types = more input views, NOT a smarter model
The model is not the bottleneck; features are. The current detector only sees
auth events (srcip-carrying, windowed into event_count / distinct_users /
events_per_user / hour). To cover a new attack type, clone
`ai-stack/pipeline/detection_consumer.py` with a feature set for that domain:

| Detector | Feed | Features | Catches |
|---|---|---|---|
| auth (exists) | sshd/PAM | events/user, distinct users | brute force, spraying |
| network (next) | conn/firewall logs | distinct dst ports, conn rate/src | port scans, sweeps |
| web | access logs | 4xx ratio, URL diversity | fuzzing, injection |
| host | FIM/syscheck (already running) | file changes/min, new bins, sudo | persistence, priv-esc |

Each writes to the same `ai-detections-*` schema with its own `ai.category`.
Dashboard/backend need zero changes — they already render category, severity,
top_srcips.

## 2. GPU arrives → swap ONLY the inference slot
Isolation Forest → autoencoder (Morpheus DFP's approach: learn to reconstruct
"normal", flag high reconstruction error). Same contract: Kafka in, detection
docs out, same index schema. Nothing upstream or downstream changes — that's
the "swap not rewrite" claim in the README; keep it true.

## 3. RAM arrives → LLM is a READER, not a pipeline stage
The LLM consumes existing `ai-detections-*` docs and writes a 2-sentence analyst
explanation back onto the doc (e.g. `ai.explanation`). The flyout displays it.
It attaches on top; it never sits in the detection path (a slow/dead LLM must
never delay detection — same reasoning as Kafka decoupling rules from AI).

## Also remember
- Detections written before Aug 2026 lack category/top_srcips (pre-enrichment).
- Mock traffic from 127.0.0.1 is never blockable (loopback guard) — attack from
  another host (VM LAN: attack ssh on this machine from the host) to demo Block IP.
- Producer needs docker group access (`sudo usermod -aG docker $USER`, re-login).
- Full design history: `docs/dashboard-plan.md`.
