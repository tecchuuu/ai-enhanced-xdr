# Failure Log & Lessons Learned — AI-Enhanced XDR Project

*Running record of every error, dead end, and design decision, captured as it happened. Feeds บทที่ 5 (สรุปผล / lessons learned). Append new entries at the bottom.*

**Format:** each entry = What happened → Why → Fix → Lesson. "Decision" entries record a choice + rationale (not a breakage).

---

## PHASE: Foundation (Steps 1–3 of project_plan.md)

### Entry 1 — Ubuntu VM setup
- **What:** Created Ubuntu VM on VMware Workstation Pro. Installed Ubuntu **Desktop (GUI), 26.04 LTS**. VM specs: 4 cores / 10–12 GB RAM / 80 GB dynamic disk (not pre-allocated). Host: Windows 11, 16 GB RAM, AMD RX 5700 XT.
- **Decisions made:**
  - Kept **26.04** despite it being new (~10 weeks old). Reasoning: the stack is containerized, so host OS version is low-stakes — containers bring their own userland and share the host kernel. Docker officially supports 26.04.
  - Went **Desktop over Server** (costs ~1.5–2 GB RAM vs headless). Reversible without reinstall via `systemctl set-default multi-user.target` / `graphical.target`.
- **Lesson:** Host OS version is low-stakes because the stack is containerized. The GUI-vs-headless RAM tradeoff is reversible at boot level, not baked in.

### Decision — Operating as root for the build
- Chose to build as **root**, consistent with pentest workflow.
- Reasoning: least-privilege is a production/multi-user/exposed-system control; this is a single-user, unexposed, snapshot-protected lab VM — that threat model is absent. Docker-group membership ≈ root anyway (`docker run -v /:/host` = trivial host access), so a non-root login isn't a meaningful privilege boundary here. **Consistency** (one user, always) matters more — mixing users causes container volume-ownership errors.
- Least privilege IS applied where it counts: inside the architecture (OpenSearch runs as non-root UID inside its container; scoped agent perms; tightly-scoped response-playbook credentials = future work).

### Entry 2 — Docker install
- **What:** Installed Docker from Docker's **official apt repo** (not Ubuntu's `docker.io`). `docker run hello-world` succeeded (needed sudo).
- **Error:** `newgrp docker` → "command not found."
- **Why:** On Ubuntu 25.10/26.04, `newgrp` was moved out of base `util-linux` into a separate `util-linux-extra` package, not installed by default.
- **Fix:** Didn't install it — `newgrp` is only a shortcut to apply a group change without re-login. Used a reboot instead (also fine pre-snapshot).
- **Secondary issue:** initial `usermod -aG docker $USER` was run from a **root shell**, so `$USER` may have resolved to `root` instead of the intended user. Re-ran targeting the user by name.
- **Lessons:** (1) Use Docker's official repo, not the distro's stale `docker.io` (which also ships old `docker-compose` syntax). (2) Stripped-down environments/images omit common binaries — don't assume a tool exists. (3) Don't run `$USER`-dependent commands from a root shell.

### Entry 3 — Wazuh cert generation
- **What:** Ran `generate-indexer-certs.yml`. All certs reported "created" successfully.
- **Error (cosmetic):** `/wazuh-certs-tool.sh: line 636: find: command not found`.
- **Why:** the minimal generator container lacks the `find` binary; it fired on one cleanup line but certs were still generated, moved, and chowned (verified by `ls`).
- **Cert ownership oddity:** files showed mixed `user:user` and `dnsmasq:systemd-journal` ownership — **NOT a bug.** The tool chowns certs to the numeric UIDs the container processes use; the host maps those numbers to whatever accounts happen to hold them. UID = a number; the name is a per-system lookup. Left as-is (chowning to the login user would break it).
- **Pre-boot requirement:** set `vm.max_map_count=262144` on the host (required by OpenSearch/indexer, else its startup check fails). Set on the HOST because containers share the host kernel.
- **Lessons:** (1) Same stripped-image pattern as Entry 2 — `find` missing. (2) A UID is just a number; container↔host ownership can look alarming but be correct. (3) Kernel params (`vm.max_map_count`) are set host-side and inherited by containers.

### Entry 4 — Wazuh first boot
- **What:** `docker compose up -d`. All 3 services (manager, indexer, dashboard) reached `Up`. Indexer log showed `started` + cluster health `GREEN`.
- **Notable:** project_plan.md predicted cert errors on first boot — **they did NOT occur.** Clean boot, because cert generation (Entry 3) completed correctly despite the cosmetic `find` error. The prediction was conservative.
- **Cosmetic log noise (all non-fatal):** OpenSearch auditlog `ERROR` (a feature not used), `0600`-permission `WARN` on bind-mounted config, Java deprecation `WARN`s, master-key `WARN`.
- **Bonus:** indexer auto-created the template for `wazuh-archives-4.x-*` — the archive index the AI pipeline depends on already exists structurally.
- **Lesson:** "Working" = the service reaches `started` / `GREEN` / `Up` and stays there — NOT "zero WARN/ERROR lines." A stack this size always mutters on cold start; the skill is distinguishing fatal from cosmetic.

### Entry 5 — MILESTONE: Wazuh stack fully operational
- Logged into dashboard at `localhost` (creds admin / SecretPassword). Overview renders.
- "No agents registered" (expected — none deployed).
- **Alert pipeline already flowing:** 45 medium + 141 low alerts from the manager's own internal/container events → proves manager → indexer → dashboard path works end-to-end BEFORE any agent. This is Claim A's "fast path" demonstrated.
- Snapshot `wazuh-stack-running` taken at this known-good state.
- **Status:** Steps 1–3 complete (VM, Docker, Wazuh). Foundation done.

### Entry 6 — logall_json edit didn't apply, then fixed
- **What:** Edited host config to `<logall_json>yes</logall_json>`, ran `docker compose restart wazuh.manager`. But the manager still read `<logall_json>no</logall_json>`.
- **Why:** the host config bind-mounts to `/wazuh-config-mount/etc/ossec.conf` (a staging path). The manager reads from `/var/ossec/etc/ossec.conf`. The container **entrypoint** copies staging→real **only on a full container start**. `docker compose restart` bounces the process WITHOUT re-running the entrypoint → new config never copied → old config still active.
- **Fix:** `docker compose up -d --force-recreate wazuh.manager` (rebuilds container, entrypoint runs, config copied). Verified with `grep` showing `yes`.
- **Then:** forced an event via `wazuh-logtest` (matched rule 5710, sshd invalid user). `archives.json` appeared at `/var/ossec/logs/archives/2026/Jul/ossec-archive-07.json`, non-zero, filling with real events (df output, CIS/SCA scan, "server started", rootcheck).
- **Key observation:** most archived events are **NON-rule events** — exactly the raw firehose the AI needs, and exactly what `alerts.json` would never contain. This demonstrates *why* the AI must consume archives, not alerts.
- **Lessons:** (1) For mounted-config changes, **`restart` ≠ recreate** — `restart` skips the entrypoint; must `--force-recreate` for config-mount edits to take effect. (2) Wazuh stores archives in date-stamped subfolders (`archives/YYYY/Mon/`) and creates them lazily on first event. (3) `archives.json` contains events `alerts.json` never would — the whole rationale for consuming archives.

### Note — docker exec container naming
- `docker exec -it wazuh.manager bash` → "No such container: wazuh.manager".
- **Why:** `docker exec` needs the **full container name** (`single-node-wazuh.manager-1`), not the compose service name.
- **Fix / lesson:** use `docker compose exec wazuh.manager bash` — compose maps short service names to real containers. `docker exec` = full container name; `docker compose exec` = short service name. Container auto-naming = `<project>-<service>-<number>`.

### Note — documentation strategy
- Didn't screenshot live during the build. Realized most evidence is **persistent** (running dashboard, container logs, terminal history, on-disk configs) → recoverable on demand, not lost. Only transient error states are gone, but those are already captured here as reasoning (higher value than screenshots).
- **Adopted:** screenshot at milestones (working states) + real bugs; keep this log for process/why. Photographing real current system state is valid whenever taken — not faking. (Faking = fabricating events/metrics that never happened.)

---

## DESIGN NOTES (for บทที่ 2 / 3 — understanding, not breakages)

### Decision — Morpheus deferred to CPU-equivalent + optional GPU demo
- AMD RX 5700 XT can't run CUDA/Morpheus locally (hardware constraint, not choice).
- Per project_plan.md: Morpheus = a GPU wrapper over ML; the ML is the substance.
- **Strategy:** implement the DFP/anomaly methodology in Python/CPU (provable on current hardware); design the pipeline to NVIDIA's DFP reference shape (Kafka-native source, auth-log ingest — matches our Wazuh→Kafka design); treat real Morpheus as an optional Colab/SIAM-GPU demo.
- **Framing for report:** "methodology implemented on CPU; GPU deployment = documented future work." Honest and markable under stated constraints.
- **Caveat:** NVIDIA's own forums report the DFP *production* example is hard to run with sparse docs — more reason to prove the ML concept in plain Python first.

### Note — "pretrained vs training" resolved (corrects v1 error)
- Verified against NVIDIA docs (Morpheus 25.06): DFP has BOTH a training and an inference pipeline, communicating via an MLflow model store. DFP trains unsupervised behavioral models **per user** (+ a generic fallback). Minimum **300 log records per user** to train that user's model.
- Even the "pretrained" DFP model is meant to be **updated with your own attack-free data per user** — there is no training-free DFP, by design (a behavioral fingerprint is meaningless without that user's data).
- DFP training runs on **CPU** (`"device": "cpu"` in the config) — small autoencoder, ~seconds/minutes.
- Truly use-as-is pretrained Morpheus models exist (phishing, sensitive-info detection) but do a **different task** than login/host anomaly detection — wrong tool for our claim.
- **Correct wording:** not "we don't train," but "we use Morpheus's DFP architecture and fit the baseline on our own data."

### Note — normalization happens in TWO layers (not just "JSON")
- **Layer 1 — Wazuh decoders (analysisd):** parse raw log text → structured fields on a common schema (e.g. `srcip`, `srcuser`, `program_name`, seen in logtest output). THIS is the SIEM parse/normalize the instructor means. Mostly built-in (hundreds of decoders) — demonstrated, not built from scratch. JSON is just the serialization of this, not the normalization itself.
- **Layer 2 — ML preprocessing (Morpheus/Python):** convert structured JSON events → numeric feature vectors before inference (scale numbers, encode categoricals). This is ML feature engineering, a different step. NVIDIA: "Any data source can be fed into DFP after some preprocessing to get a feature vector per log/data point."

### Note — model performance does NOT transfer across data types
- A model validated on one data type (e.g. network-flow benchmark like CICIDS/NSL-KDD) does **not** prove it works on another (e.g. auth logs). Different features, different domain.
- The **generality is in the METHOD** (an autoencoder/isolation forest learns "normal" for whatever coherent data it's given), NOT in transferring a fitted model across data types.
- **Implication:** prove the model on the data type the pipeline actually uses (auth logs / archives.json). Any public benchmark must be presented as a SEPARATE, clearly-labeled offline capability check — never as evidence of auth-log performance, and never drawn as flowing through Wazuh.

### Decision — Dropped CICIDS2017 / network-flow benchmarks entirely
- **Choice:** use **auth-log data only** — mock login data first (labeled, provable), then real `archives.json`. No CICIDS2017, no NSL-KDD, single coherent lane.
- **Reasoning:** the benchmark is a *different data type* than the pipeline processes (network-flow vs auth/host log). Performance does not transfer across domains, so a benchmark number would be misleading rather than evidence of auth-log detection. One coherent lane = better methodology, not a gap.
- **Defensible answer if asked "why no public benchmark":** "benchmarks are a different data domain; I validated on the data type my pipeline actually processes."
- **Doc impact:** proposal edit 3-B (CICIDS offline lane) in คำสั่งแก้ไข_proposal.md is now stale — rewritten to single auth-log lane.

---

## PHASE: AI Model (Step 4 of project_plan.md)

### Entry 7 — Step 4: Isolation Forest proof-of-concept (mock auth data)
- **What:** Ran offline Isolation Forest (scikit-learn, CPU, Python venv `ml-venv`) on 200 mock normal logins + 5 planted anomalies (3am logins / weird IP octet / high failed-attempts). Features: hour, src_ip_octet, failed_attempts. `contamination=0.03`.
- **Result:** caught **5/5 planted anomalies (100% detection)** with **2 false positives** (normal 5pm logins misflagged) → 7 flagged of 205 total. ≈1% FPR.
- **Meaning:** the unsupervised model learned "normal" from the data and flagged deviations **without being told what an attack is** — demonstrates **Claim B** (AI catches what rules miss). Ran on CPU in ~seconds, no GPU/Morpheus needed.
- **On the false positives:** expected and *useful* — gives a real False Positive Rate to report + explain in บทที่ 4 (instructor pass-criterion). Driven partly by `contamination=0.03` (told it ~3% is anomalous → it flags ~6-7 regardless of how many real anomalies exist). Tuning `contamination` trades FPR against missed detections — that tradeoff IS the evaluation science.
- **Lesson:** a working anomaly detector is not "zero false positives" — it's "catches the real ones at an acceptable FPR." Seeing FPs is the honest, reportable result.
- **Status:** Step 4 core (mechanism) PROVEN on mock data. Remaining in Step 4: (a) optionally tune contamination, (b) run IF on REAL auth events from archives.json (requires generating login activity + feature extraction). Autoencoder (AE) = step-up after IF.

### Entry 8 — Real auth data: pipeline proven, agent deployed
- **What:** Installed OpenSSH server on the VM, deployed Wazuh agent (`ubuntu-vm`, ID 001) pointing at `WAZUH_MANAGER='localhost'` (manager's published port 1514 forwards into the container). Agent reached **Active**; confirmed three ways: `(4102): Connected to the server`, `agent_control -l` showing Active, and dashboard "Active (1)".
- **Result:** generated real failed SSH logins → captured via **journald** (not flat `/var/log/auth.log` — Ubuntu 26.04 routes sshd to the journal; the agent's logcollector monitors journal entries) → decoded by manager → written to `archives.json`. 91 auth events extracted with `srcip`/`srcuser`.
- **Note on decoder coverage:** newer OpenSSH emits `"drop connection ... penalty: failed authentication"` messages that match decoder `sshd` but only trigger generic rule **1002** with NO `srcip`/`srcuser` fields. The parseable events are the classic `Failed password for invalid user X from IP` lines (rule **5710**), plus PAM **5503**. Feature extraction must filter for events that actually carry `data.srcip`.
- **Lesson:** "the decoder recognised it" ≠ "the fields you need were extracted." Always check for the specific fields your features require, not just that an event was decoded.

### Entry 9 — Windowed Isolation Forest on real data: weak result, diagnosed (NEGATIVE RESULT)
- **What:** Aggregated 91 real auth events into 1-minute windows (28 windows: 16 quiet, 12 active), features = event_count / distinct_users / max_level / hour. Ran IF with `contamination=0.15`. Compared model flags against windows where Wazuh brute-force rule **5712** fired.
- **Result:** AI flagged 5 windows, rule 5712 flagged 3, nominal delta = 2. **But only 1 of those 2 was meaningful** — the 05:05 window (attack ramp-up, flagged a minute *before* the rule fired at 05:06 = earlier detection). The other (05:24: 2 events, 0 distinct users) was noise forced by the contamination setting.
- **KEY HONEST FINDING:** on the **slow/low-and-slow attack** — the exact scenario the thesis targets — the model did **NOT** outperform the rule. Windows 05:25–05:32 were almost entirely unflagged; the only slow-phase window flagged (05:30) was one rule 5712 also caught. Recorded as a genuine negative result rather than spun as success.
- **Diagnosed causes:**
  1. **`distinct_users` feature was broken** — returned 0 for windows containing only PAM/5503 events, because those carry no `srcuser` field. This dropped the *single strongest* slow-attack signal (username cycling: admin/root/oracle/postgres/...).
  2. **1-minute windows too short.** Attempts were spaced 25–40s apart → 1–2 events per window, statistically indistinguishable from noise. A slow attack's signature only emerges over a **longer** aggregation window.
  3. **Dataset too short/small** — 91 events over 27 minutes. At 5-min windows that's only ~6 windows; IF on <10 samples is not statistically meaningful.
- **Also structurally limited:** all events came from a single source IP (127.0.0.1) and were ~100% failures — no successful-login baseline. The intended "normal" phase of the generator used a wrong password too, so it also logged as failures. Unsupervised anomaly detection needs a normal baseline to deviate *from*.
- **Fixes applied in v2 script:** recover username from `full_log` via regex when the decoder didn't populate `srcuser`; add volume-independent features (`events_per_user`, `user_diversity`) that expose slow attacks regardless of rate; make window size configurable for **multi-scale windowing** (short windows catch bursts, long windows catch low-and-slow).
- **Lesson:** a feature that silently returns 0 is worse than a missing feature — it looks valid and quietly destroys the signal. Verify feature values against a handful of raw events before trusting a model's output.

### Rule-based baseline measured (for บทที่ 4 comparison)
- Rule **5712** ("brute force trying to get access") fired **3 times total**: `05:06:00` and `05:07:05` (the fast burst — caught reliably), and `05:30:23` (a single hit early in the slow attack).
- **Interpretation for the report (do not overclaim):** rule-based detection caught the fast burst reliably, but during the slow distributed attack it produced only **one** correlated alert while ~9 further attempts generated isolated level-5 events with no brute-force correlation. Correct framing = *"rules caught a fragment, missed the pattern"* — NOT *"rules caught nothing."*
- **On whether rules could catch slow attacks at all (honest position for บทที่ 2/4):** they can, *if* someone anticipates the pattern and sets a wide-enough threshold. The weaknesses are that (a) any fixed threshold can be gone under — attackers throttle by default without needing to know the number, (b) rules only catch *predicted* patterns, and (c) thresholds low enough to catch stealth attacks generate heavy false positives (the Alert Fatigue problem in §2.1.5). Anomaly detection scores *degree* of deviation instead of applying a fixed cutoff.
- **Also worth stating:** automated response (Block IP / isolate host) is downstream of detection — if nothing detects the slow attack, no response fires. Detection is the bottleneck.

---

## PHASE: Dashboard + Writeback (Step 5 of project_plan.md)

### Entry 10 — Step 5: custom dashboard + AI writeback loop working
- **Stack chosen:** FastAPI (Python) backend + single-file HTML/JS frontend. Rationale: the whole AI layer is already Python, so a Python backend shares the venv and can import the ML code directly; a TS/Bun backend (e.g. Elysia) would split the project across two languages for no benefit. Frontend kept plain for now — swappable to React later without touching the data layer.
- **Why a backend at all:** OpenSearch is HTTPS + self-signed cert + basic auth. A browser-only page can't reach it (CORS, cert rejection, and credentials would be exposed in client-side JS). The backend holds the credentials and serves clean JSON.
- **Built:**
  - `/api/alerts/rule` — Wazuh rule alerts from `wazuh-alerts-4.x-*`
  - `/api/alerts/ai` — model detections from `ai-detections-*`
  - `/api/alerts/combined` — both streams merged, tagged by `source`
  - `/api/stats` — counts for summary cards
  - `writeback.py` — runs Isolation Forest on windowed archive data and bulk-writes flagged windows into `ai-detections-2026.07.18` tagged `source: morpheus_ai`, rule ID **100001** (the 100000+ custom range from proposal §3.5). **This closes the writeback loop from project_plan.md: archive → model → tagged detections → OpenSearch → dashboard.**
- **Dashboard design:** split timeline with a central time axis — rule alerts left, model detections right, bucketed by minute. Where the model fired and no rule did, the left shows "no rule fired" and the right card gets a "missed by rules" badge. The comparison is visual rather than requiring a manual diff of two tables.

### Entry 11 — FIRST REAL CLAIM B RESULT (and an important reframing)
- **Initial run showed `MODEL ONLY: 0`.** Diagnosed: the dashboard's rule column used `min_level=5`, which includes rule **5710** — that fires on *every* failed login, so some rule alert existed in every window the model flagged. Zero gaps by construction.
- **Key insight:** a level-5 5710 is not the rule system *declaring an attack*, it is a log entry. The rule that declares an attack is **5712 at level 10**. Changed the comparison to `min_level=10` = "did the ruleset escalate to an attack declaration?" — the correct question.
- **Result after the fix — `MODEL ONLY: 2`:**
  - `05:32` — model flagged (4 events, 2 users), **no rule fired**. This is the tail of the slow attack: the ruleset stopped escalating while the model kept flagging the behaviour. **Genuine Claim B evidence on real pipeline data.**
  - `05:24` — also model-only but weak (2 events, **0 distinct users**); attributable to `contamination=0.15` on sparse data. Recorded as a false positive, not presented as a catch.
  - At `05:06`, `05:07`, `05:30` **both** fired — rules caught the fast burst and the model agreed. This strengthens rather than weakens the story: the model *extends* the ruleset rather than contradicting it.
- **SECOND, ARGUABLY STRONGER RESULT — alert reduction:** the dashboard surfaced **384 rule alerts, overwhelmingly dpkg package noise (level 7)**, versus **5 model detections**. That is Alert Fatigue reproduced live on our own data — the exact problem cited in §2.1.5 (83% of analysts overwhelmed, ~70 min per investigation). Framing for บทที่ 4: *384 raw rule alerts → 5 prioritised detections* = alert prioritisation demonstrated.
- **Honest wording for the report (do NOT overclaim):** rules were not silent — they emitted many level-5 events. The claim is that the ruleset **did not escalate** those events to an attack declaration during the slow phase, while the model did. Also: model scores give a *ranking* (−0.766 for the 34-event burst down to −0.555), i.e. degree of deviation rather than a binary threshold — the concrete advantage over fixed-threshold rules.
- **Lesson:** the choice of comparison baseline determines whether a result exists at all. Comparing against "any rule fired" produced a null result; comparing against "the ruleset declared an attack" produced a real one. State the baseline explicitly in the report — an unstated baseline makes a metric meaningless.

### Note — /root permissions vs the desktop user
- `file:///root/xdr-dashboard/dashboard.html` → Firefox: "Access to the file was denied."
- **Why:** `/root` is mode 700; Firefox runs as the desktop user (`magi`), not root, so it cannot traverse into root's home.
- **Fix:** serve over HTTP (`python3 -m http.server 8080`) instead of `file://` — bypasses filesystem permissions entirely and matches how a frontend would really be served.
- **Pattern (third occurrence of the root-vs-user theme):** building as root means GUI apps running as the desktop user cannot read files under `/root`. Same root cause as the earlier `$USER`/`~` path issues.

---

## PHASE: Streaming pipeline (Steps 6–7 of project_plan.md)

### Entry 12 — Kafka deployed (KRaft mode), listener misconfiguration diagnosed
- **What:** Added Kafka (`apache/kafka:3.9.0`) in a **separate compose file** (`~/ai-stack/ai-stack.yml`), deliberately not in Wazuh's compose file, so the Wazuh base stack stays pristine and independently restartable, and can still be diffed/re-pulled against upstream.
- **KRaft mode, no ZooKeeper:** modern Kafka handles cluster coordination internally. One container instead of two, less RAM. Worth noting because most tutorials still show a separate ZooKeeper container.
- **ERROR — container crash-looped (`Restarting (1)`):**
  ```
  advertised.listeners cannot use the nonroutable meta-address 0.0.0.0.
  Use a routable IP address.
  ```
- **Why:** Kafka has two distinct listener settings. `listeners` = what address to **bind** to (`0.0.0.0` = all interfaces, correct). `advertised.listeners` = what address to **tell clients** to connect on — `0.0.0.0` is meaningless to a client, so Kafka refuses to start. The stack trace showed the failure in `kafka.tools.StorageTool`, i.e. during **storage formatting before the server starts**; at that point the image derives the advertised value from `listeners`, so `0.0.0.0` propagated and tripped validation *before* `KAFKA_ADVERTISED_LISTENERS` could apply.
- **Fix:** `KAFKA_LISTENERS: PLAINTEXT://:9092,CONTROLLER://:9093` — empty host instead of `0.0.0.0`. Same binding behaviour, but nothing bogus to derive. Also `down -v` to clear the half-written volume from the failed format attempt, then `up -d`.
- **Verified:** `Transition from STARTING to STARTED`, `Kafka Server started`, port 9092 published. Topic `wazuh-archives` created and listed.
- **Lesson:** bind-address and advertised-address are different concepts; a value that is valid for one can be invalid for the other. Also: read *where* in the stack trace a failure occurs — this failed in the storage-format tool, not the server, which is what explained why the override appeared to be ignored.

### Entry 13 — Streaming pipeline wired end-to-end (Steps 6–7 complete)
- **Stub first:** a dummy producer/consumer (`stub_test.py`) sent and read back 5 messages with **no ML involved**, proving the Kafka pipe worked before anything depended on it. Same one-thing-at-a-time approach used throughout.
- **CONSTRAINT FOUND — Filebeat supports only ONE output at a time.** Filebeat is already shipping to the Wazuh indexer (that is what populates the dashboard), so Kafka cannot simply be added as a second output. Options were: (a) a Python tailer to Kafka, (b) a second Filebeat instance, (c) switch Filebeat's output to Kafka — which would **break the dashboard**.
  - **Chose (a).** `archive_producer.py` runs `docker exec <manager> tail -F` on `archives.json` and publishes each event to the `wazuh-archives` topic. Proves the streaming architecture, requires no change to the working Wazuh stack.
  - **For the report:** document the single-output constraint as a finding, and state that a production deployment would use a **second Filebeat instance** with a Kafka output. This is an honest architectural note, not a workaround being hidden.
- **Verified live:** triggered an SSH login failure and watched events flow through in real time — `rule 5710 lvl 5 testuser`, `rule 5503 lvl 5 127.0.0.1`, etc. Wazuh → archive → Kafka, continuously.
- **Consumer built** (`detection_consumer.py`): Kafka → window aggregation → Isolation Forest → writeback to `ai-detections-*` tagged `morpheus_ai` / rule 100001. This is the CPU-equivalent of the Morpheus streaming stage: *Kafka source → deserialize → preprocess → inference → writeback*.
- **Deliberate guard:** the consumer refuses to score until it has **≥10 windows** buffered. This directly encodes the lesson from Entry 9 — fitting Isolation Forest on 2–6 samples produces a meaningless result. Better to print "not enough windows yet" than to emit a number that looks valid.
- **DESIGN NOTE for บทที่ 3 (state explicitly):** the consumer **refits** Isolation Forest over a rolling buffer of recent windows rather than loading a pre-trained baseline. NVIDIA's DFP separates training and inference into two pipelines communicating through an MLflow model store; here both occur in one process because the dataset is small and the baseline short-lived. The architecture is equivalent — the separation is a **scale** concern, not a correctness one.
- **Result:** the architecture in proposal Figure 3.1 is now running live: `Wazuh → archive → producer → Kafka → consumer → Isolation Forest → OpenSearch → dashboard`, with Morpheus remaining the documented GPU deployment target.

### Note — service persistence across VM restarts
- Docker services (Wazuh ×3, Kafka) auto-start via `restart: always` / `unless-stopped`; the Wazuh agent auto-starts via systemd. **The four Python processes do not** (uvicorn, http.server, producer, consumer) — they would need re-running after every reboot.
- Mitigation: a `start_all.sh` launching all four with `nohup ... &`, output redirected to `/root/logs/*.log` (viewable live with `tail -f`). For an **unattended overnight run**, systemd units are the better answer since they also auto-restart on crash — a consumer that dies at 02:00 would otherwise silently waste the whole run.

---

## PHASE: Overnight evaluation run

### Entry 14 — Three bash/Python bugs found while launching the overnight run
All three were caught before the run mattered, but each would have silently degraded or destroyed the dataset.

**Bug 1 — `sleep` given a negative value (script died immediately).**
- `traffic.log` showed only `Usage: sleep NUMBER[SUFFIX]...` and the generator process was absent from `ps`.
- Cause: jitter was applied as `sleep $(( gap + (RANDOM % 11) - 5 ))`. With `gap=3`, a jitter of −5 produces `sleep -2`, which is an error, and the script exited.
- Fix: floor the value at 1 — `local j=$(( gap + (RANDOM % 11) - 5 )); [ $j -lt 1 ] && j=1; sleep $j`.
- Lesson: randomised jitter must be bounded on both sides. A jitter range wider than the base value can go negative.

**Bug 2 — `local` with inline arithmetic evaluated in the wrong order (silent, worse).**
- After fixing bug 1, the log showed `NORMAL period for 40 min` and `>>> ATTACK` **in the same second**. The 40-minute baseline period lasted zero seconds.
- Cause: `local secs=$1 end=$(( $(date +%s) + secs ))` — bash expands the arithmetic for `end` **before** `secs` has been assigned, so `secs` was empty, `end` evaluated to "now", and the `while` loop exited immediately.
- Fix: split into two statements — `local secs=$1` then `local end=$(( $(date +%s) + secs ))`.
- **Why this one was dangerous:** it produced no error at all. The script "worked", but would have generated back-to-back attacks with no baseline — destroying the exact property the run existed to create. Only the timestamps in the log revealed it.
- Lesson: in bash, `local a=$1 b=$((a+1))` does not do what it looks like. Assign, then compute.

**Bug 3 — Python stdout buffering made the consumer look dead.**
- `consumer.log` was empty all night despite the process being alive with 1:13 of CPU time.
- Cause: when stdout is redirected to a file rather than a terminal, Python buffers output in ~8 KB blocks. All the consumer's prints were sitting in an unflushed buffer.
- Fix: run with `python -u` (unbuffered), or add `flush=True` to prints. The producer was unaffected because its print already used `flush=True`.
- **Diagnosis lesson:** an empty log does not mean a dead process. Verify against the process's *actual output target* — here, querying OpenSearch directly (`ai-detections-*/_count` → 34) proved the consumer had been working correctly the whole time.

### Entry 15 — Host suspension interrupted the run (environmental, not a code fault)
- Timeline shows `04:10:02 NORMAL period for 100 min` (due to end ~05:50) followed by the next attack at `08:47`. A ~3-hour gap.
- Cause: the Windows host went to sleep, suspending the VM mid-`sleep`. On resume, the elapsed-time check had already passed, so the generator continued correctly from where it was.
- **Impact: minimal.** All three attack episodes executed. The gap reduced baseline traffic density but reads as an additional quiet period, which is legitimate baseline data.
- Fix for future runs: disable sleep in Windows power settings before an unattended run.
- Worth reporting in บทที่ 4 as a run condition, for transparency.

### Entry 16 — Decision: stopped after one cycle rather than looping
- The generator loops indefinitely by design, but was stopped after the first ~7.5-hour cycle.
- **Reasoning:** anomaly detection defines "anomalous" as *rare*. Repeating an identical attack pattern every six hours would progressively fold those patterns into the learned baseline — after several cycles the model would correctly conclude that a brute-force at 04:00 is normal for this system, and stop flagging it. Additional cycles would add repetition, not variety, and would actively dilute the signal.
- One cycle produced three attack episodes at three distinct rates, ~7.5 hours of baseline, and 4,057 events — sufficient. Further variety would require *randomising* attack times and intensities, not repeating the same schedule.

### Entry 17 — RESULT: detection degrades with attack speed (see results log R10)
- Ground truth (UTC): episode 1 fast (3 s) 21:07–21:10; episode 2 slow (30 s) 01:47–01:55; episode 3 very slow (75 s) 03:55–04:11.
- Rule 5712: **2 alerts** in episode 1, **2 alerts** in episode 2, **0 alerts** in episode 3. The alert series terminates at 01:54 and never resumes.
- Model: **4** windows in episode 1, **11** in episode 2, **2** in episode 3.
- **This is the project's central claim demonstrated on real pipeline data with independent ground truth**, replacing the thin single-session result of Entry 11.
- **Caveat recorded honestly:** episode-3 detections are weak-signal (2–3 events, 0–1 distinct users per window) because 75-second spacing yields roughly one attempt per minute. The claim is that rules produced zero alerts while the model produced detections in the window — not that the model confidently characterised episode 3.

---

## PHASE: Repository hygiene + console revamp (2026-08-28)

### Entry 18 — Wazuh CA private key published to a public repo (mis-anchored .gitignore)
- `.gitignore` contained `config/wazuh_indexer_ssl_certs/`. A pattern containing a slash is anchored to the repository root, so it matched `./config/...` and never `wazuh/config/...`, which is the actual location. The rule looked correct and did nothing.
- Consequence: `root-ca.key`, `admin-key.pem`, and the indexer/manager/dashboard private keys were tracked from the initial commit `020b39c` and pushed to a public GitHub repository.
- Practical risk was low (self-signed lab certs, NAT'd VM, not internet-facing) but the exposure was real, and `SecretPassword` — the published Wazuh default — is still inline in `dashboard/writeback.py`.
- **Fix:** re-anchored the rule to `wazuh/config/wazuh_indexer_ssl_certs/`, `git rm -r --cached` on the directory, then regenerated the full chain via `generate-indexer-certs.yml` and restarted the stack. New root CA serial `6AFA7BD9...` replaces `0FC7A26A...`; containers restarted after issuance, so the new chain is in effect.
- **Reasoning for not rewriting history:** once the certs are regenerated, the exposed keys authenticate nothing. `git filter-repo` would buy tidiness, not security, and costs a force-push. Judged not worth it.
- **Lesson for บทที่ 5:** a security tool leaked its own trust anchor through a config file that read as correct. Ignore rules must be verified with `git check-ignore -v`, not by reading them. This is a concrete instance of the project's own thesis — the failure was invisible to inspection and only surfaced under a test.

### Entry 19 — Python venv broke silently on directory rename
- Renamed `~/xdr-project` to `~/ai-enhanced-xdr`. `start_all.sh` derives its own root from `$BASH_SOURCE`, so it survived; the virtualenv did not.
- Every script in `ml-venv/bin/` carries an absolute shebang (`#!/home/magi/xdr-project/ml-venv/bin/python3`) and `pyvenv.cfg` records the creation path. 14 files affected.
- A grep over `*.py` and `*.sh` reported no hardcoded paths and was wrong — venv console scripts have no file extension and were never matched.
- **Fix:** rewrote the path across `ml-venv/bin/*` and `pyvenv.cfg`. `python -m venv --clear` would achieve the same and is the more reliable habit.

### Entry 20 — Console: invalid icon names, wrong spacer color, unvalidated palette
- Three `iconType` values do not exist in EUI 119: `visBarHorizontal`, `visBarVerticalStacked`, `securitySignal`. EUI renders a placeholder for unknown types, which appeared as a broken-image glyph *inside empty-state panels only* — so it surfaced exactly where a chart had no data, and read as two unrelated bugs rather than one.
- All three bar charts hardcoded `stroke: "#1a1a19"` as the inter-bar spacer, but the EUI Borealis dark surface is `#0B1628` (navy). The separator was the wrong color in the only mode in use.
- Palette re-validated against each surface. The existing rule/AI pair passed colorblind separation (worst adjacent ΔE 13.0), but `#bd271e` scored **2.99:1 contrast — below the 3:1 floor**, which is why high-severity badges read as muddy rather than urgent.
- **Changes:** rule alerts `#c17e15` → `#d95926` (mustard against navy is a complementary clash), high severity `#bd271e` → `#e66767`, AI teal `#0ca58c` unchanged. Light mode was given independently validated steps rather than an automatic flip of dark.
- Stat figures moved to text ink with an 8px colored dot carrying identity: four large saturated numerals meant none of them read as the headline. "Model-only catches" is now the hero tile, since it is the number the project exists to produce.

### Note — detection plane moved off root; project relocated
- Everything now runs as `magi` (added to the `docker` group). The producer no longer requires `sudo docker`, closing the item recorded in the earlier `/root` permissions note.
- Project path is `~/ai-enhanced-xdr`. Kafka's compose file moved from `/root/ai-stack/` into the repository; volume `ai-stack_kafka_data` was preserved because the Compose project name derives from the parent directory name, which did not change.
- The Wazuh stack still runs from `~/wazuh-docker/single-node` (project `single-node`). Moving it into the repo would resolve to project `wazuh` and therefore to different volumes, silently discarding every indexed alert and AI detection. **Left in place deliberately** — this is a trap worth stating in บทที่ 5.
- Datasets recovered from `/root` (`archive_18.json`, windowed CSVs, run logs) now live in `~/root-backup/`, outside the repo so they are not committed. `scripts/*.py` and `dashboard/writeback.py` were repointed.

### Note — the 34 AI detections predate enrichment
- Detections from the overnight run carry no `category` and no `top_srcips`; both fields were added after that run. The category chart is therefore empty at every available time range, and the detections themselves (2026-07-19) fall outside even the 30-day window.
- Not a defect: `detection_consumer.py` writes both fields at lines 169/188. But **the enrichment path has never been observed producing output**, and confirming it requires a fresh traffic run. Until then the category feature is claimed, not demonstrated.

---

## BUILD STATUS (last updated: 2026-08-28 — repo hygiene + console revamp)
- **Steps 1–3 COMPLETE:** Ubuntu 26.04 VM (VMware) → Docker → Wazuh stack running, dashboard verified, `logall_json: yes`, `archives.json` populating. Snapshot: `wazuh-stack-running`. **Now operating as `magi`** (docker group), not root; project lives at `~/ai-enhanced-xdr`, Wazuh stack at `~/wazuh-docker/single-node`.
- **Step 4 COMPLETE (mock) / PARTIAL (real):**
  - Mock: Isolation Forest caught 5/5 planted anomalies, ~1% FPR, CPU. Claim B on controlled labelled data.
  - Real: SSH server + Wazuh agent (`ubuntu-vm`) deployed and Active; endpoint → agent → manager → decode → `archives.json` proven; feature engineering working (JSON → windowed features). One genuine model-only detection at 05:32 + one acknowledged false positive.
- **OVERNIGHT EVALUATION COMPLETE:** ~7.5 h run, 4,057 events, three attack episodes at 3 s / 30 s / 75 s spacing with independent ground-truth timestamps. **Rules detected episodes 1 and 2 (2 alerts each) and produced zero alerts for episode 3; the model produced detections in all three.** 34 AI detections written. This is the headline result (R10).
- **Results banked for บทที่ 4:** (1) mock IF 5/5 @ ~1% FPR; (2) **R10 — detection degradation by attack speed, ground-truth verified**; (3) alert reduction (384 rule alerts → 5 model detections in the earlier session); (4) anomaly *scores* provide ranking, not binary thresholds; (5) live streaming pipeline demonstrated end-to-end.
- **KNOWN DATA LIMITATIONS (state in บทที่ 5):** single-host lab data, one source IP (127.0.0.1 — `srcip` unusable as a feature), single monitored endpoint, episode-3 detections are weak-signal, host suspension created a ~3 h baseline gap.
- **REMAINING WORK:**
  1. **SAD diagrams (Step 8)** — Context Diagram, DFD Level 1, Data Dictionary, State Diagram. **Required บทที่ 3 artifacts.** Pure tracing of a system that already exists; no code. Highest priority — this is the largest documentation gap, and it has not moved.
  1a. **Fresh traffic run from a second host** — switch the VM adapter from NAT to bridged, then attack from the host machine. This single run unblocks three things at once: real `srcip` values (loopback is refused by the block-ip guardrail, so Block IP is currently undemonstrable), the first AI detections carrying `category`/`top_srcips`, and a non-empty console. See the enrichment note above.
  1b. **Web detector on Apache :80** — roadmap item #1, the `web` row (4xx ratio, URL diversity). Chosen over further auth-domain work because simple brute force is precisely what the ruleset already catches; the AI side needs an evasive web variant to have anything to add. Clone `detection_consumer.py` with the HTTP feature set; the dashboard and backend need no changes.
  2. **Write up บทที่ 4 and 5** from `results_log_chapter4.md` and this file. Raw material is complete; the prose is not written.
  3. **Local LLM alert explanation** — pretrained download from Hugging Face (Typhoon-7B / Llama-3.2). SIAM goal #3.
  4. **Autoencoder** — model step-up, comparison against Isolation Forest.
  5. Optional: multi-scale windowing analysis (1 / 5 / 15 min) on the overnight dataset — the data now supports it and it directly addresses the slow-attack question.
- **Security debt outstanding:** `dashboard/writeback.py` still carries `admin`/`SecretPassword` inline and is tracked in git; move to `.env` alongside the other credentials. The stale July cert copy under `wazuh/config/wazuh_indexer_ssl_certs/` is dead since regeneration and should be deleted so there is one source of truth.
- **Fixes to apply before any future unattended run:** `python -u` for the consumer (unbuffered logging); disable host sleep; randomise attack times/intensities rather than repeating a fixed schedule.
- No Morpheus locally (deployment target; optional Colab GPU demo later).
