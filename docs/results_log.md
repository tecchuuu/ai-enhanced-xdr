# บทที่ 4 — Results Log (ผลการดำเนินงาน)

*Companion to `failure_log.md`. That file records **process** (what broke, why, decisions) and feeds บทที่ 5. **This** file records **results** (metrics, evidence, figures) and feeds บทที่ 4.*

**How to use:** each result = what was measured → the number → where the evidence lives → how to state it honestly. Add new results as they are produced. Screenshot filenames are placeholders — rename to match your own files.

---

## Evidence index (screenshots taken so far)

| # | Evidence | Shows | Used in |
|---|---|---|---|
| E1 | Wazuh dashboard overview | Stack running, 45 medium + 141 low alerts pre-agent | R1 |
| E2 | `docker compose ps` | All 3 services `Up` | R1 |
| E3 | Indexer boot log | Cluster health `GREEN`, `wazuh-archives-4.x-*` template created | R1 |
| E4 | `archives.json` `ls` + `tail` | Archive populating with non-rule events | R2 |
| E5 | Agent page — `ubuntu-vm` Active | Endpoint → manager path working | R3 |
| E6 | Isolation Forest terminal output (mock) | 5/5 anomalies caught, 2 FP | R4 |
| E7 | `extract_auth.py` output | JSON → structured features (91 events) | R5 |
| E8 | FastAPI `/api/alerts/combined` JSON | Both streams tagged by source | R6 |
| E9 | Split-timeline dashboard | Rule vs model, "missed by rules" badge | R7, R8 |
| E10 | 5712 timestamp list | Rule-based baseline coverage | R7 |

---

## R1 — Claim A: the pipeline works (infrastructure)

**Measured:** whether events flow Endpoint → Wazuh Manager → Indexer (OpenSearch) → Dashboard.

**Result:** All three services reached `Up`; indexer cluster health `GREEN`. 186 alerts (45 medium + 141 low) were generated and displayed **before any agent was deployed**, from the manager's own internal events — proving the manager → indexer → dashboard path end-to-end.

**Evidence:** E1, E2, E3

**How to state it:** "The single-node Wazuh deployment (manager, indexer, dashboard) was brought up under Docker Compose and verified operational. Alert flow from manager to indexer to dashboard was confirmed prior to agent deployment."

---

## R2 — Archive ingestion enabled (the AI data source)

**Measured:** whether `logall_json: yes` produces `archives.json` containing events that `alerts.json` would not.

**Result:** `archives.json` created at `/var/ossec/logs/archives/2026/Jul/` and populated. Inspection showed the majority of archived entries are **non-rule events** (`df -P` output, CIS/SCA scan results, rootcheck completion, service start) — events that never appear in `alerts.json` because they match no rule.

**Evidence:** E4

**How to state it:** "Enabling `logall_json` produced a full event archive containing both rule-matched and unmatched events. Inspection confirmed that most archived entries do not appear in the rule-based alert log, establishing the archive as the appropriate input for anomaly detection intended to identify events the ruleset does not flag."

**Why it matters:** this is the technical precondition for the entire AI claim. Reading `alerts.json` instead would restrict the model to events the rules already caught.

---

## R3 — Endpoint agent deployment

**Measured:** whether a Wazuh agent on the host forwards real authentication events to the manager.

**Result:** Agent `ubuntu-vm` (ID 001) registered and reached **Active**. Confirmed three independent ways: agent log `(4102): Connected to the server ([localhost]:1514/tcp)`, manager-side `agent_control -l` listing the agent as Active, and the dashboard agent page. Real SSH authentication failures were captured via **journald** and decoded by the manager.

**Evidence:** E5

**How to state it:** "A Wazuh agent was deployed on the monitored host and confirmed active. Authentication events generated on the endpoint were collected via journald, transmitted to the manager, decoded, and written to the event archive."

---

## R4 — Claim B on controlled data (mock auth logs)

**Measured:** whether an unsupervised model flags planted anomalies without being told what an attack is.

**Result:**

| Metric | Value |
|---|---|
| Normal records | 200 |
| Planted anomalies | 5 |
| Anomalies detected | **5 / 5 (100%)** |
| False positives | 2 |
| False positive rate | **≈1%** (2 / 200 normal) |
| Model | Isolation Forest, `contamination=0.03` |
| Runtime | seconds, CPU only |

Features: hour-of-day, source IP octet, failed-attempt count. Planted anomalies were 03:00-hour logins from unusual IP ranges with elevated failure counts.

**Evidence:** E6

**How to state it:** "On a controlled dataset of 200 normal and 5 anomalous authentication records, the Isolation Forest detected all 5 planted anomalies with 2 false positives (≈1% of normal records). The model was not given labels or attack signatures; it learned the distribution of normal behaviour and flagged deviations from it."

**On the false positives (do not hide these):** they are expected and useful. Two normal 17:00 logins were flagged. The `contamination=0.03` parameter instructs the model that ~3% of records are anomalous, so it flags approximately 6–7 regardless of how many true anomalies exist. Tuning `contamination` trades false-positive rate against missed detections; that trade-off is itself the evaluation.

---

## R5 — Feature engineering from live archive data

**Measured:** whether real Wazuh JSON events can be converted into model-ready features.

**Result:** 91 authentication events extracted from `archives.json` with fields `timestamp`, `rule_id`, `level`, `srcip`, `srcuser`. Aggregated into time windows with derived features: `event_count`, `distinct_users`, `max_level`, `hour`, `events_per_user`, `user_diversity`.

**Evidence:** E7

**How to state it:** "Archived events were parsed and converted into per-window numeric feature vectors. This corresponds to the preprocessing stage of the AI pipeline, in which structured log events are transformed into inputs suitable for inference."

**Implementation note worth reporting:** the initial distinct-user feature returned 0 for windows containing only PAM events, because those events do not populate `srcuser`. Usernames were recovered from `full_log` by pattern matching. A feature that silently returns a valid-looking zero is more damaging than a missing feature.

---

## R6 — Alert integration and writeback

**Measured:** whether model output can be written back into the storage layer, tagged and distinguishable from rule alerts.

**Result:** Flagged windows written to index `ai-detections-2026.07.18` with `source: morpheus_ai` and rule ID **100001** (the 100000+ custom range specified in §3.5). Both streams are queryable and merge-able through the API, each carrying a `source` tag.

**Evidence:** E8

**How to state it:** "Model detections are written back to the indexer in a dedicated index, tagged by source and assigned rule IDs in the custom range, so that AI-generated alerts remain distinguishable from rule-generated alerts at query and display time. This implements the alert-deduplication design described in §3.5."

---

## R10 — PRIMARY RESULT: detection degradation by attack speed (overnight run)

**This supersedes R7 as the headline comparison.** R7 (single 27-minute session) is retained as an early result; R10 is the credible one, with ground-truth timestamps and three attack episodes at controlled speeds.

**Method.** A traffic generator produced ~7.5 hours of authentication activity: quiet baseline periods (successful logins every 1–2.5 min, occasional single mistypes) interleaved with three brute-force episodes at deliberately different rates. Attack start/stop times were logged independently, giving ground truth. **4,057 events** were captured and streamed through the live pipeline (Wazuh → Kafka → Isolation Forest → OpenSearch). Local time is UTC+7; the table uses UTC to match indexed timestamps.

**Ground truth (from generator log):**

| Episode | Attempts | Spacing | Local time | UTC window |
|---|---|---|---|---|
| 1 — Fast | 25 | ~3 s | 04:07–04:10 | 21:07–21:10 |
| 2 — Slow | 15 | ~30 s | 08:47–08:55 | 01:47–01:55 |
| 3 — Very slow | 12 | ~75 s | 10:55–11:11 | 03:55–04:11 |

**Result:**

| Episode | Speed | Rule 5712 alerts | Model detections | Outcome |
|---|---|---|---|---|
| 1 — Fast | 3 s | **2** (21:08, 21:09) | **4** windows (21:07–21:10) | both detect |
| 2 — Slow | 30 s | **2** (01:49, 01:54) | **11** windows (01:47–02:02) | both detect; model far broader coverage |
| 3 — Very slow | 75 s | **0** | **2** windows (03:55, 04:07) | **rules silent, model detects** |

**Rule-based alerts after 01:54 UTC: none.** The 5712 alert series terminates entirely; no brute-force alert was raised at any point during episode 3.

**Evidence:** OpenSearch query output for `ai-detections-*` (34 detections with timestamps and anomaly scores); OpenSearch query output for `wazuh-alerts-*` filtered on `rule.id:5712`; generator log with attack start/stop times.

**How to state it:**

> "Three brute-force episodes were generated at controlled rates of approximately 3, 30 and 75 seconds between attempts, with start and stop times recorded independently as ground truth. Rule-based correlation (rule 5712) detected the first two episodes, raising two alerts in each case, and produced **no alerts during the third**. The anomaly model produced detections within all three episodes, including four windows during the fast episode, eleven during the slow episode, and two during the very slow episode. Detection by the signature-based ruleset therefore degrades monotonically as attack rate decreases, reaching zero at 75-second spacing, while the anomaly model continued to produce detections across the same period."

**Secondary finding — coverage density.** Even where rules did detect (episode 2, an 8.5-minute attack), they produced 2 alerts against the model's 11 flagged windows. Rules alert at isolated moments when a threshold is crossed; the model tracks the behaviour across the episode. Relevant to incident scoping, not only to detection.

**Honest caveat — state this explicitly.** The episode-3 detections are weak-signal: those windows contain only 2–3 events with 0–1 distinct users, because 75-second spacing yields roughly one attempt per minute, which resembles ordinary login activity. The defensible claim is that **the ruleset produced zero alerts while the model produced detections within the attack window** — not that the model confidently characterised episode 3 as an attack. Report the timestamps and let them stand.

**Why this generalises (for บทที่ 2/4).** Rule 5712 correlates on a fixed threshold (N failures within T seconds). An attacker pacing attempts below that threshold evades it, and lowering the threshold to catch slow attacks raises false positives across normal activity. Anomaly detection scores degree of deviation rather than applying a fixed cut-off, so it degrades gradually rather than failing outright. Note also that automated response is downstream of detection: with no alert raised during episode 3, no blocking action would have been triggered.

**Run-condition note (report for transparency).** The host machine suspended between approximately 05:50 and 08:47 local time, interrupting traffic generation for around three hours. The generator resumed on wake and all three episodes executed. The interruption reduced baseline traffic density in that interval but did not affect any attack episode; the gap reads as an additional quiet period.

---

## R7 — Rule-based vs model coverage (initial 27-minute session)

**Measured:** which detections the ruleset escalated to an attack declaration, versus which windows the model flagged.

**Baseline definition (state this explicitly in the report):** the rule-based baseline is **rule level ≥ 10**, i.e. the ruleset declaring an attack (e.g. rule 5712, "brute force trying to get access"). Level-5 events such as rule 5710 ("attempt to login using a non-existent user") are logged for *every* failed login and do not constitute an attack declaration.

**Result:**

| Window (UTC) | Rule ≥ lvl 10 | Model flagged | Notes |
|---|---|---|---|
| 05:06 | ✔ 5712 | ✔ (score −0.766, 34 events, 4 users) | fast burst — both detect |
| 05:07 | ✔ 5712 | ✔ (score −0.647, 10 events, 4 users) | fast burst — both detect |
| 05:24 | ✘ | ✔ (score −0.598, 2 events, 0 users) | **false positive** — see below |
| 05:30 | ✔ 5712 | ✔ (score −0.576, 6 events, 2 users) | both detect |
| 05:32 | ✘ | ✔ (score −0.555, 4 events, 2 users) | **model-only, genuine** — tail of slow attack |

**Summary:** rule-based 3 windows, model 5 windows, **model-only 2** (of which 1 is a genuine detection and 1 an acknowledged false positive).

**Evidence:** E9, E10

**How to state it honestly:** "Rule-based detection reliably identified the rapid burst phase, producing brute-force alerts at 05:06, 05:07 and 05:30. During the slower, spaced phase of the attack the ruleset ceased escalating to attack-level alerts, while the anomaly model continued to flag the behaviour, producing one detection (05:32) with no corresponding rule-based alert. A second model-only detection (05:24) is attributed to the contamination parameter operating on a sparse dataset and is reported as a false positive."

**Do NOT claim:** that rules detected nothing during the slow phase. They emitted numerous level-5 authentication-failure events. The claim is that the ruleset did not **escalate** those events to an attack declaration, while the model did.

**Supporting argument for บทที่ 2/4 — why this generalises:** rule-based correlation depends on a fixed threshold (N failures within T seconds). An attacker throttling below that threshold evades it, and lowering the threshold to catch slow attacks increases false positives. Anomaly detection scores the *degree* of deviation rather than applying a fixed cut-off. Note also that automated response is downstream of detection: if no detection fires, no blocking action is triggered.

---

## R8 — Alert volume reduction (alert-fatigue mitigation)

**Measured:** how many alerts an analyst would face from the ruleset, versus how many prioritised detections the model surfaces.

**Result:**

| Source | Count |
|---|---|
| Rule-based alerts indexed | **384** |
| Of which level 3 | 178 |
| Of which level 7 (largely package-management noise) | 97 |
| Of which level 5 | 99 |
| Of which level 10 (attack declarations) | 5 |
| Model detections | **5** |

**Evidence:** E9 (dashboard header counters), E8

**How to state it:** "The ruleset produced 384 alerts over the evaluation period, the majority being low-severity operational events such as package-management activity. The anomaly model surfaced 5 prioritised detections over the same period. This illustrates the alert-prioritisation problem described in §2.1.5, in which alert volume rather than detection capability is the limiting factor for analyst effectiveness."

**Additional point:** model output is a continuous anomaly **score** (−0.766 to −0.555 across the flagged windows), allowing detections to be ranked by severity rather than treated as a binary threshold result.

---

## R9 — Streaming pipeline (Kafka integration)

**Measured:** whether archived events can be streamed continuously into the detection pipeline, rather than read from a file in batch.

**Result:** Kafka broker deployed in KRaft mode (no ZooKeeper) on a separate compose stack. Topic `wazuh-archives` created. A producer tails the manager's live archive and publishes each event; a consumer reads the topic, aggregates events into time windows, runs Isolation Forest, and writes flagged windows back to OpenSearch. Verified live — an SSH authentication failure generated on the endpoint appeared in the producer output within seconds (`rule 5710 lvl 5 testuser`, `rule 5503 lvl 5 127.0.0.1`).

**Pipeline realised:** `Endpoint → Agent → Wazuh Manager → archives.json → Producer → Kafka → Consumer → Isolation Forest → OpenSearch → Dashboard`

**Evidence:** producer terminal output; Kafka `Kafka Server started` log; topic listing

**How to state it:** "The streaming layer specified in the system architecture was implemented using Apache Kafka in KRaft mode. Archived events are published to a dedicated topic and consumed by the detection process, which performs windowed feature aggregation and inference before writing detections back to the indexer. This corresponds to the Morpheus streaming stage sequence of source, deserialisation, preprocessing, inference and writeback, executed on CPU."

**Architectural constraint to report honestly:** Filebeat supports only a single output at a time and is already configured to ship to the Wazuh indexer. Adding Kafka as a second Filebeat output is therefore not possible without either replacing the indexer output — which would disable the Wazuh dashboard — or running a second Filebeat instance. For this demonstration a Python tailer performs the equivalent function; a production deployment would use a second Filebeat instance with a Kafka output.

**Training/inference design note:** the consumer refits Isolation Forest over a rolling buffer of recent windows rather than loading a pre-trained baseline from a model store. NVIDIA's DFP separates training and inference into two pipelines communicating through MLflow. Both occur in one process here because the dataset is small and the baseline short-lived; the architecture is equivalent and the separation is a scale concern.

**Safeguard:** the consumer does not score until at least 10 windows are buffered. Fitting Isolation Forest on fewer samples produces output that appears valid but is not statistically meaningful (see failure log Entry 9).

---

## R11 — Web detection lane: content discovery + path traversal (real off-host IP)

**Measured:** whether the same anomaly method, given a web feature view, detects web attacks the ruleset buries in noise — and whether detections carry a real, blockable source IP.

**Setup:** Apache on :80, access log fed to Wazuh via `<localfile>`, `web_detection_consumer.py` (rule 100002, `web-streaming`) running alongside the auth consumer on its own Kafka consumer group. Light "normal" traffic ran as a baseline. Attacker: off-host (Kali, real srcip `192.168.1.133`). Ground truth (UTC, 2026-09-09): content-discovery scan at **07:32**, path-traversal requests at **07:34**.

**Result:**

| Window | Attack | Detector output |
|---|---|---|
| 07:32 | gobuster content discovery (~3152 requests) | rule 100002, score **−0.85**, `request_count 3152, distinct_urls 3152, error_ratio 0.999`, srcip 192.168.1.133 → one detection |
| 07:34 | path-traversal curls | rule 100002, `category path_traversal` (T1083), srcip 192.168.1.133 |

**Alert reduction (the headline):** the single content-discovery scan produced **~3000+ rule alerts** (one per 404'd request — the Alert-Fatigue problem, §2.1.5) but **one** AI detection. This is a sharper version of R8's 384→5: **~3000 rule alerts → 1 prioritised detection**.

**Real source IP:** unlike R1–R10 (all `127.0.0.1`), these detections carry a real off-host IP (`192.168.1.133`), which partially addresses Known-limitation 1 and makes automated Block-IP demonstrable.

**Honest notes (from failure log Entry 22):**
- The scan window was initially mis-labelled `web_injection` rather than `content_discovery` — a heuristic ordering bug (payload regex checked before aggregate scan shape), since fixed. The *detection* was always correct; only the category label was.
- The scan also leaked into the auth detector (rule 100001, counted as brute_force) because the auth consumer kept any event carrying `srcip`, which web events also have. Fixed so the lanes are disjoint. Both are recorded as findings, not hidden — they demonstrate the "silently-wrong, invisible until tested" theme.

**How to state it:** "The same unsupervised method, given a web-request feature view, detected a content-discovery scan and a path-traversal attempt from an external host. A single scan generated over three thousand rule alerts but one prioritised AI detection, reproducing the alert-prioritisation result of R8 at larger scale. Bringing the second lane online also surfaced — and the project corrected — a data-domain leak between the auth and web detectors, itself an instance of the silently-invisible failure mode the project studies."

---

## R12 — Autoencoder vs Isolation Forest (swappable inference slot)

**Measured:** whether an autoencoder — the model class NVIDIA Morpheus DFP wraps — detects the same auth anomalies as Isolation Forest on identical windowed features, and built as a drop-in for a swappable inference slot.

**Setup:** both models implement one interface, `fit_score(X, contamination)`, in `ai-stack/pipeline/models/`; the live consumers pick one via `DETECTOR_MODEL` in `.env` (no code change to swap). Autoencoder = a PyTorch reconstruction network (device-aware: CPU here, CUDA on the SIAM H100), high reconstruction error = anomaly. Offline comparison on the 28-window auth dataset (`windowed_features.csv`), contamination 0.15.

**Result:**

| Model | Flagged | Agree w/ rule 5712 | Model-only |
|---|---|---|---|
| Isolation Forest | 5 | 3 | 2 (05:24, 05:32) |
| Autoencoder (PyTorch) | 6 | 3 | 3 (05:25, 05:26, 05:32) |

Both flag all 3 rule windows (05:06, 05:07, 05:30) **and** the meaningful slow-attack tail at 05:32 (agreement: both=4, IF-only=05:24, AE-only=05:25/05:26). The autoencoder additionally covers two low-and-slow windows IF missed, giving slightly broader coverage of exactly the slow-attack phase the project targets; IF's only unique flag (05:24) is the weak near-false-positive already noted in R7/Entry 11.

**How to state it:** "Two independent unsupervised methods — Isolation Forest and a PyTorch autoencoder — were run on identical windowed features through a shared, swappable inference interface. Both reproduced all rule-based detections and both flagged the slow-attack tail, indicating the model-only detections are a property of anomaly detection generally rather than of one algorithm. The autoencoder additionally covered two further low-and-slow windows, consistent with its expected strength on the paced-attack scenario the project targets, and is expected to widen that margin on the larger datasets available in the SIAM environment. It is the same model class NVIDIA Morpheus DFP deploys, and occupies the same swappable interface slot on GPU."

**Architecture note:** swapping models is now a configuration change (`DETECTOR_MODEL=autoencoder`), not a code edit — the "swap not rewrite" claim made literal (ROADMAP rule 2). Morpheus's dfencoder drops into the same slot on SIAM.

**Reproduce:** `ml-venv/bin/python scripts/compare_models.py`

---

## R13 — Deployment on the SIAM H100 environment (real hardware)

**Measured:** whether the whole system — proven locally on CPU — actually deploys and runs end-to-end on the provided production-grade environment, and detects a real attack there.

**Environment:** SIAM AI VM `oa-hgx-h100-bu-02` — Ubuntu 24.04, 14 vCPU / 220 GB RAM / 3.3 TB disk / **NVIDIA H100 80GB** / **BlueField-3 DPU**, reached over VPN+SSH. Docker + NVIDIA Container Toolkit installed; GPU confirmed visible inside containers (`docker run --gpus all ... nvidia-smi` → H100).

**Result:** full stack brought up under project namespace `luckyfive_*` — Wazuh manager/indexer/dashboard (indexer cluster `green`), Kafka (KRaft), the streaming pipeline (producer + auth & web consumers) and the FastAPI backend. Admin password changed from the default. A Wazuh agent (ID 001) was deployed on the VM and reached **Active**. A real SSH invalid-user attack was then run and verified through **both** paths:
- **AI/archive path:** producer logged the events to Kafka (`rule 5710 lvl 5` for each attempted user) → consumer windowing.
- **Alert path:** after fixing the credential propagation (see failure log), 6 `rule 5710` alerts indexed into `wazuh-alerts-*` (total 186 → 493) and rendered in the dashboard.

**Evidence:** `siam_events_5710.png` (invalid-user alerts in the dashboard), `siam_overview.png`, `siam_stack_gpu.png` (`docker ps` + `nvidia-smi` H100).

**Honest notes:**
- Source IP is loopback (`127.0.0.1`) — the attack was run on-box because the local VM has no network route to the SIAM VM. Real off-host `srcip` was already demonstrated locally (R11); this result is about proving the *deployment*, not the source IP.
- **GPU compute is currently blocked** on the SIAM VM (CUDA Error 802, GPU Fabric State stuck — a provider-side passthrough issue, ticket raised). The CPU pipeline is unaffected; Morpheus, the local LLM, and the autoencoder-on-GPU are pending that fix.

**How to state it:** "The system, developed and proven on a constrained local VM, was deployed without architectural change onto the sponsor's H100 environment: the full ingestion→streaming→detection→storage→dashboard chain ran end-to-end and detected a live attack on the production-grade box. This validates the containerised, swap-not-rewrite design. GPU-accelerated components await a provider-side GPU-initialisation fix; the CPU implementation runs in the interim."

---

## R14 — Autoencoder on the H100: same verdicts, 3.7x faster fit

**Measured:** whether moving the inference slot onto real GPU hardware changes *what* the system detects, or only *how fast* it decides — and whether the swap needs any code change.

**Setup:** identical 28-window auth fixture (`data/windowed_features.csv`, now committed so both machines score the same data), identical seed (42), `contamination=0.15`, same registry entry `models/autoencoder.py`. Only the hardware differs. The SIAM GPU became usable on 2026-10-10 after the provider resolved the fabric/passthrough fault that caused CUDA Error 802 (failure log Entry 23 follow-up); `torch 2.11.0+cu128` reports `cuda.is_available() == True`, Fabric State `N/A`, Compute Mode `Default`, 0 MiB in use by other tenants.

**Result:**

| Run | Device | Fit time | Flagged | Agree w/ rule 5712 | IF-only | AE-only |
|---|---|---|---|---|---|---|
| Local VM | CPU | 3.494 s | 6 | 3/3 | 1 | 2 |
| SIAM | NVIDIA H100 80GB HBM3 | **0.939 s** | 6 | 3/3 | 1 | 2 |

Flag-for-flag identical across both devices — same 6 windows, same agreement structure with Isolation Forest (`both=4`), same 3/3 coverage of the rule-declared brute-force windows. Fit time fell 3.7x.

**Why that is the point, not a disappointment:** a GPU is a throughput device, not a different model. 28 windows x 5 features is far below the size where an H100 can stretch, and the near-identical numbers are evidence the device-aware code path is *correct* — the same seeded network converges to the same reconstruction errors on either backend. The speedup is therefore the floor, not the ceiling: it is what GPU execution buys at trivial scale, and the headroom (80 GB HBM3, 0% utilised at this size) is what makes the larger runs in "still to be produced" feasible.

**Swap cost:** zero code change. `DETECTOR_MODEL` selects the slot, and `autoencoder.py` resolves `cuda` vs `cpu` at fit time. The same file ran on both machines untouched — the "swap not rewrite" claim, now demonstrated across hardware as well as across models.

**Method note:** fit timing is taken after `torch.cuda.synchronize()`. CUDA kernels are asynchronous, so timing without the barrier measures queue-submission, not computation, and would have reported a fictitious speedup.

**How to state it:** "Relocating the inference slot from CPU to an NVIDIA H100 required no code modification and produced identical detection verdicts at 3.7x faster model fit, confirming that GPU acceleration in this architecture is a performance property rather than a change in detection behaviour."

---

## R15 — LLM alert explanation live on the H100 (local model, no data egress)

**Measured:** whether the explanation layer — built in September against a deterministic `mock` provider — produces usable analyst prose when a real model is dropped behind it, and at what latency.

**Setup:** Ollama on the SIAM VM serving **gemma3:12b** (Google DeepMind open weights, 9.2 GB resident), fully GPU-resident on the H100 (`ollama ps`: `100% GPU`, 10,427 MiB of 81,559 MiB). `EXPLAINER_PROVIDER=ollama`. The explainer was exercised through `scripts/test_explainer.py`, which feeds it two documents shaped exactly like real `ai-detections-*` docs — one per lane — plus one follow-up question, with no Wazuh, Kafka or OpenSearch running. This isolates the explanation layer as an independent unit.

**Result — latency:**

| Call | Time |
|---|---|
| First explanation (includes model load into VRAM) | 7.01 s |
| Warm explanation (auth lane) | 0.80 s |
| Warm explanation (web lane) | 1.13 s |
| Warm follow-up question | 1.23 s |

**Result — quality.** The model grounded its explanations in the supplied numbers and invented nothing. On the web detection it picked `/admin` and `/.git/config` out of the top-URLs list unprompted and named them as the reconnaissance signal — the one piece of genuine analyst judgement in the output, and not something the `mock` template produces. Asked whether the detection was a false positive, it declined to overclaim and stated plainly that it had no historical data on the IP or accounts, which is correct: the explainer is given one document and nothing else.

**One grounding error, found and fixed.** The first run reported an anomaly score of **-0.71** as *"just below the threshold (-0.5)"* — backwards. The prompt had supplied the score and the threshold and left the comparison to the model; on negative numbers a 12B model gets it wrong. The fix computes the verdict in code (`_score_line`) and states it outright — *"0.21 PAST the flag threshold of -0.5 — a strong detection"*. On re-run the model correctly called it strong and *"likely not a false positive"*. Worth recording as a method point: **where a numeric comparison decides the analyst's conclusion, compute it and assert it; do not ask the model to reason about it.**

**Architecture claim upheld.** No change to the detection path. The explainer remains a reader of already-written detection documents, invoked on demand from the flyout — a slow or dead model delays nothing, which is why a 7 s cold start is acceptable here and would not be inside the pipeline. Switching from `mock` to a GPU-hosted 12B model was one environment variable; the prompt, the field flattening, and the writeback are shared across providers.

**Privacy note for the report:** the model runs on the same VM as the pipeline. Source IPs, usernames and URLs never leave the host. The alternative `anthropic` provider would export those fields to a third party — available, deliberately not used.

**Honest notes:**
- Still phrasing slips: the model writes that a score is "significantly higher than our threshold" where *further past* is meant, and compresses "17 events per user across 2 users" into "a user experienced 17 failed login attempts". Neither is fabrication; both are imprecision, and they are the reason the explanation is positioned as triage assistance rather than as a finding.
- Explanation quality is assessed qualitatively on two representative documents. A scored rubric over a larger sample of detections remains future work.
- `gemma4:12b` was tried first and crashed — Ollama's bundled llama.cpp does not yet support that architecture (released the previous day). Model choice here favours a mature tag over a new one; the provider is indifferent to which.

**How to state it:** "The explanation layer was validated with a 12-billion-parameter open-weight model hosted locally on the H100, producing analyst-ready prose in under 1.3 seconds per detection with no detection data leaving the host. Replacing the deterministic template provider with the model required one configuration change and no modification to the detection pipeline."

---

## R16 — NVIDIA Morpheus's DFP autoencoder in the same inference slot (three-model comparison)

**Measured:** whether the inference slot is genuinely model-agnostic — specifically whether NVIDIA's own production detection model can occupy it with no change to ingestion, windowing, storage or dashboard — and whether three independent methods agree about what is anomalous.

**Setup:** `morpheus-core 25.06` installed in a conda environment on the SIAM VM (it links RAPIDS and the MRC C++ engine, so it cannot be pip-installed), exposing `morpheus.models.dfencoder.AutoEncoder` — the autoencoder the Morpheus Digital Fingerprinting pipeline is built around. Wrapped as one new registry file, `models/morpheus_dfencoder.py`, implementing the existing `fit_score(X, contamination) -> (flags, scores)` contract. Identical 28-window fixture, identical `contamination=0.15`, identical features for all three models.

**Result:**

| Model | Flagged | Agrees with rule 5712 | Device | Fit time |
|---|---|---|---|---|
| Isolation Forest | 5 | 3/3 | CPU (scikit-learn) | — |
| Autoencoder (this project, PyTorch) | 6 | 3/3 | H100 | 0.755 s |
| **Morpheus dfencoder (DFP)** | **5** | **3/3** | **H100** | **0.209 s** |

Pairwise agreement:

| Pair | Both | A only | B only |
|---|---|---|---|
| Isolation Forest vs Autoencoder | 4 | 1 | 2 |
| **Isolation Forest vs Morpheus dfencoder** | **5** | **0** | **0** |
| Autoencoder vs Morpheus dfencoder | 4 | 2 | 1 |

**The finding.** Morpheus's dfencoder and Isolation Forest selected the *identical* set of 5 windows — total agreement, neither flagging anything the other missed. These are unrelated methods: Isolation Forest is a tree ensemble measuring isolation depth; dfencoder is a neural autoencoder measuring reconstruction error under GaussRank scaling and swap-noise training. Independent methods converging on the same windows is evidence that those windows are genuinely anomalous in the data rather than artefacts of one algorithm's inductive bias. All three models also covered all 3 rule-declared brute-force windows.

**The architecture claim, now demonstrated rather than asserted.** Adding NVIDIA's model required exactly one new file in `models/` and one registry line. Zero changes to `detection_consumer.py`, `web_detection_consumer.py`, `archive_producer.py`, the writeback schema, the backend, or the dashboard. The deliberate choice was to adopt Morpheus's *model* rather than its *pipeline runtime*: the runtime would have replaced ingestion and windowing already built and evaluated here, and would have left nothing to compare against. Stated plainly in บทที่ 3 as a scoping decision — this project supplies the pipeline, Morpheus supplies one interchangeable model.

**Honest notes:**
- **Fit times are not a like-for-like benchmark.** The two networks differ in architecture, epoch count (300 full-batch vs 50 mini-batch) and preprocessing. The numbers show both run on the GPU at sub-second scale; they do not establish that one model is faster than the other.
- **28 windows is far too small for dfencoder.** It is built for per-user fingerprinting over large event volumes. Training a neural autoencoder on 28 rows means the agreement figures above are about this fixture, not a general claim. The three-way comparison needs re-running on a substantially larger dataset before any conclusion about relative accuracy.
- dfencoder emits `Initializing zero-element tensors is a no-op` because the feature set is entirely numeric — it allocated empty categorical-embedding layers. Harmless, and a reminder that these features use none of its categorical machinery, which is where DFP's real strength lies.
- Early stopping is disabled (`patience=-1`) as there is no validation split at this data size.
- This is the model library, not the Morpheus pipeline runtime, so no claim is made to end-to-end cuDF-accelerated streaming.

**How to state it:** "NVIDIA Morpheus's Digital Fingerprinting autoencoder was integrated as a third interchangeable model in the detection pipeline's inference slot, requiring one new adapter file and no modification to any other component. On identical data it selected exactly the same anomalous windows as the Isolation Forest baseline — agreement between two methodologically unrelated detectors — and both matched the rule engine's brute-force declarations in full."

---

## Known limitations (carry these into บทที่ 5)

State these explicitly — they strengthen credibility rather than weaken it:

1. **Single source IP (auth evaluation).** All *overnight-run* traffic originated from `127.0.0.1`, so `srcip` was constant and unusable as a feature there. Partially addressed on 2026-09-09: the web-lane run (R11) used a real off-host attacker (`192.168.1.133`); full multi-source validation remains future work.
2. **No successful-login baseline.** Generated "normal" traffic used incorrect credentials, so all captured events are failures. A genuine normal baseline of successful logins would improve the model's notion of normal.
3. **Short observation window.** Approximately 27 minutes of events (91 records). At 5-minute aggregation this yields only ~6 windows, below the sample size at which Isolation Forest output is statistically meaningful. The 05:24 false positive is a direct consequence.
4. **Single host.** One monitored endpoint; no multi-agent or multi-user behavioural variation.
5. **GPU used for the inference slot only.** The autoencoder now fits on the SIAM H100 (R14), but the rest of the chain — ingestion, Kafka, rules, dashboard — remains CPU, by design (§3 of the sponsor brief). NVIDIA Morpheus is the remaining GPU-native component.
6. **BlueField-3 DPU unreachable.** The DPU is provisioned but cannot be managed — the host's `rshim` driver is broken, so nothing can be deployed onto its ARM complex. The network lane is therefore not demonstrated; if the fault is not resolved, the fallback is a software Zeek/Suricata sensor emitting the same EVE-JSON records, without hardware offload.

---

## Still to be produced (gaps in บทที่ 4)

| Result needed | Status | Blocking |
|---|---|---|
| Longer evaluation run (60+ windows, normal baseline, multiple attack episodes) | not started | ~5–6 h unattended traffic generation (overnight) |
| Multi-scale windowing comparison (1 / 5 / 15 min) | not started | needs the longer run above |
| Streaming throughput measurement (events/sec) | pipeline ready | needs sustained traffic to measure |
| Response time / MTTR measurement | not started | automated response playbook |
| LLM alert-explanation quality assessment | **PARTIAL 2026-10-10 (R15)** — qualitative, 2 documents | a scored rubric over many detections |
| Autoencoder comparison vs Isolation Forest | **DONE 2026-09-09 (R12)** | — |
| Autoencoder on real GPU hardware | **DONE 2026-10-10 (R14)** | — |
| NVIDIA Morpheus model in the inference slot | **DONE 2026-10-10 (R16)** | — |
| Three-model comparison on a large dataset | not started | a dataset of thousands of windows |
| Web detection lane (second coherent slice) | **DONE 2026-09-09 (R11)** | — |
