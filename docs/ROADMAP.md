# Roadmap — what is built, and how the next pieces attach

Status as of 2026-11-01. Three rules, in priority order, then the work still open.

## 1. More attack types = more input views, NOT a smarter model
The model is not the bottleneck; features are. Each lane windows one log source into
one-minute features (`ai-stack/pipeline/features.py`, shared by the live detectors and
the evaluation). To cover a new attack type, add a lane with a feature set for that
domain, the way the web lane cloned the auth lane:

| Detector | Feed | Features | Catches | Status |
|---|---|---|---|---|
| auth | sshd/PAM | events/user, distinct users, max level, hour | brute force, spraying, distributed, low-and-slow | live as `auth-detector` (CPU) and `morpheus-auth` (Morpheus DFP, GPU); evaluated R10, R18; on the Morpheus runtime R19 |
| web | nginx/apache access logs | request rate, URL diversity, 4xx ratio, POST ratio | scans, fuzzing, login brute force, traversal | live as `web-detector`; validated R11 (real off-host attacker); evaluated R17 (AIT-LDS), R18 (lab). The SIAM VM serves no web traffic, so it idles there |
| network | conn/firewall logs | distinct dst ports, conn rate/src | port scans, sweeps | **out of scope** (decided 2026-10-17, failure log Entry 32) |
| host | FIM/syscheck (already running) | file changes/min, new bins, sudo | persistence, priv-esc | not started |

Each lane writes the same `ai-detections-*` schema with its own `ai.category` and
rule id (auth = 100001, web = 100002). The console renders category, severity and
top_srcips for any lane unchanged; lane-specific window fields (e.g. web's
`top_urls`) need a few lines in `_fmt_ai()` and the alert flyout.

**Web traffic on a new host:** feed the web server's access log to Wazuh (mount its log
directory into the manager, or an agent `<localfile>` with `log_format apache`); the
`web-detector` service is already running. Attack from another host with `ffuf`
(content discovery), `hydra http-post-form` (login brute force), `sqlmap` (injection).

## 2. Swap ONLY the inference slot
Kafka in, detection documents out, same index schema: nothing upstream or downstream
changes when the model does. That is the "swap, not rewrite" claim; keep it true.

**Done.** The slot is a registry (`ai-stack/pipeline/models/`): Isolation Forest, a
PyTorch autoencoder (CPU/GPU) and **Morpheus DFP** (`dfencoder`), one interface,
selected by `DETECTOR_MODEL`. Head-to-head: R12 (IF vs autoencoder), R14 (same verdicts,
3.7× faster fit on the H100), R16 (all three on the fixture). On real-size labelled
data DFP came out best on the SSH lane — the only model to catch low-and-slow guessing
(R18) — and best or tied-best on every AIT web scenario (R17).

**The runtime too (R19).** Beyond the model, the SSH lane also runs on Morpheus's own
pipeline runtime (`ai-stack/morpheus/auth_pipeline.py`, service `morpheus-auth`) beside
the CPU consumer, which stays as the baseline. Its dataframe stages run in Morpheus CPU
mode because cuDF crashes in the engine's worker threads on this driver (Entry 41).

## 3. The LLM is a READER, not a pipeline stage
It consumes existing `ai-detections-*` documents and writes an analyst explanation back
onto the document (`ai.explanation`); follow-up questions go through
`/api/explain/chat`. It never sits in the detection path — a slow or dead LLM must
never delay detection — and it never acts. The flagged-or-not verdict is computed in
code and given to it (the fix for the grounding error in R15).

**Live on `ollama`** (gemma3:12b on the H100, about 7 s cold and 0.8–1.2 s warm; R15).
`OLLAMA_CONTEXT_LENGTH=4096` is required, or model load crashes (Entry 28). `mock`
remains the no-model fallback. `anthropic` (hosted Claude) is wired but untested, and
would send detection fields off-box. One model was tested; comparing models was out of
scope (report Chapter 5).

## Data
SIAM does not supply datasets; they are sourced independently
(`docs/dataset_selection.md`). AIT-LDS v2.0 serves the **web lane** (R17): its attacked
server has almost no SSH activity (Entry 38). The **SSH lane** — and web attacks AIT
lacks (SQL injection, XSS, traversal, HTTP brute force) — is evaluated on the lab
dataset (`lab/`, R18), every line replayed through the real Wazuh ruleset.

## Next, in order of value
1. **Per-user fingerprints at scale** — DFP per user and per host, as Morpheus's reference workflow does, once there are hundreds of records per account.
2. **Real, multi-host traffic** — measure false alarms where normal is noisy (the lab's and AIT's normal users are scripted).
3. **Multi-scale windows** (5 and 15 minutes) — push the detection floor below one attempt every six minutes.
4. **One combined score** for signatures and models, so a single crafted request a signature flags and an anomalous minute reinforce each other.
5. **Morpheus on the GPU end to end** with NVIDIA's tested container image (cuDF dataframe stages), then the web lane on the Morpheus runtime too.
6. **A working unblock** — a custom active-response script on the agent whose "add" removes the DROP, so the console can undo a block (today it records the request and gives the command; Entry 45). Or blocks that expire.
7. **Local time for the "off-hours" category** — it uses UTC hours (SETUP §5).
8. **Robust training and drift detection** against baseline poisoning and changing behaviour.
9. **Score the LLM's explanations** with a rubric over many detections; harden the prompt against instructions injected through log fields.
10. **Production console security** — SSO with roles, HTTPS, a least-privilege OpenSearch account, the shipped default passwords changed (`docs/security.md`).
11. **Throughput and response time** under sustained load.
12. **The host (FIM) lane**, and a network lane if a DPU becomes reachable.

## Also remember
- Detections written before Aug 2026 lack category/top_srcips (pre-enrichment).
- Attacks from the host itself come from `::1` / `127.0.0.1`, which the console refuses to block. To show a real block, attack from another machine or from a container on a private Docker network (SETUP §8; verified 2026-11-01).
- Console colors live in `dashboard/frontend/src/theme/palette.js`, one validated set per color mode. Do not add a hex anywhere else — dark is not a flip of light.
- Full design history: `docs/dashboard-plan.md`.
