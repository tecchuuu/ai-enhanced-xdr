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

### Entry 18 — RESOLVED: hardware constraint lifted, SIAM AI provisioned H100 + BlueField-3 (Sep 2026)

**What changed.** SIAM AI Cloud delivered the promised resources (consent form signed; window 2 Sep – 30 Nov 2026): an Ubuntu 24.04 VM with 14 vCPU / 224GB RAM / 3.4TB disk / **1× NVIDIA H100 80GB (passthrough)** / **1× NVIDIA BlueField-3 DPU (passthrough)**, over VPN+SSH. The VM is shared with another student group.

**What this resolves.** Three constraints logged earlier are now lifted, and the log should show the resolution rather than have the old entries edited:
- **Entry (Decision — Morpheus deferred to CPU-equivalent + optional GPU demo):** the deferral reason — no local CUDA GPU (AMD RX 5700 XT) — no longer applies. Morpheus moves from "documented deployment target" to *actual deployment* on the H100. **The original entry stays as written** (it was correct when made); this entry is its resolution.
- **RAM as binding constraint:** true on the 10–12GB local VM, not on the 224GB provided VM. Heap caps / sequential startup were local survival tactics, not design choices.
- **Local LLM kept off-box (tiny model / API):** the H100 runs a real 20–70B model locally. LLM alert explanation (SIAM goal #3) is now deployable, not a compromise.

**What it does NOT change (guard against scope creep).**
- The one-sentence scope and the coherent-slice rule are unchanged. Having a big GPU is not a reason to widen the core; domain coherence, not compute, drove that decision.
- The CPU proof-of-method (mock IF 5/5 @ ~1% FPR; R10 ground-truth-verified degradation) still stands alone as Claim B, and remains the fallback if the GPU/DPU work runs short. Deployment on real hardware is an *addition*, not a replacement.

**Partial reversal to record honestly (see "Decision — Dropped CICIDS2017 / network-flow benchmarks entirely").** That decision was correct *for the auth-log lane* — network-flow benchmarks don't transfer to host/auth data, and mixing domains in one model is feature soup. It is **not** reversed for the auth lane. However, the BlueField-3 now makes a *separate* network lane viable (Suricata on the DPU → network flows → separate Kafka consumer → separate model). In that lane, and only that lane, network-flow data (incl. CICIDS2017 as an offline benchmark) becomes relevant again — as a second coherent slice, never merged with auth. The original "dropped entirely" wording should be footnoted to this effect, not deleted: it was right about not forcing network data through the auth pipeline.

**New constraints introduced by the provided environment (log these as live risks).**
- Shared VM: isolate in Docker, coordinate ports, never attack outside own containers; H100 + DPU shared, so no assumption of exclusive access.
- Possible egress lockdown: test `curl github.com` early; `scp` over VPN as fallback.
- Hard deadline 30 Nov: hardware-bound work (Morpheus deploy, DPU lane) is now the critical path; VM contents vanish at window close.
- Consent form clause 4 puts data loss on the student → continuous git push + external backup.
- Long jobs in tmux/screen (VPN drop kills bare SSH sessions).

**Diagnosis lesson (for บทที่ 5).** A resource constraint that shapes early architecture decisions is not a failure to hide — the honest record is "constrained → designed a CPU-provable equivalent → constraint later lifted → deployed the real thing," which demonstrates the design was sound independent of the hardware it eventually ran on. The CPU equivalence result is *more* valuable now, not less: it proves the method wasn't dependent on the H100.

---

## PHASE: Repository hygiene + console revamp (2026-08-28)

### Entry 19 — Wazuh CA private key published to a public repo (mis-anchored .gitignore)
- `.gitignore` contained `config/wazuh_indexer_ssl_certs/`. A pattern containing a slash is anchored to the repository root, so it matched `./config/...` and never `wazuh/config/...`, which is the actual location. The rule looked correct and did nothing.
- Consequence: `root-ca.key`, `admin-key.pem`, and the indexer/manager/dashboard private keys were tracked from the initial commit `020b39c` and pushed to a public GitHub repository.
- Practical risk was low (self-signed lab certs, NAT'd VM, not internet-facing) but the exposure was real, and `SecretPassword` — the published Wazuh default — was still inline in `dashboard/writeback.py` at the time (since moved to `.env`; see BUILD STATUS).
- **Fix:** re-anchored the rule to `wazuh/config/wazuh_indexer_ssl_certs/`, `git rm -r --cached` on the directory, then regenerated the full chain via `generate-indexer-certs.yml` and restarted the stack. New root CA serial `6AFA7BD9...` replaces `0FC7A26A...`; containers restarted after issuance, so the new chain is in effect.
- **Reasoning for not rewriting history:** once the certs are regenerated, the exposed keys authenticate nothing. `git filter-repo` would buy tidiness, not security, and costs a force-push. Judged not worth it.
- **Lesson for บทที่ 5:** a security tool leaked its own trust anchor through a config file that read as correct. Ignore rules must be verified with `git check-ignore -v`, not by reading them. This is a concrete instance of the project's own thesis — the failure was invisible to inspection and only surfaced under a test.

### Entry 20 — Python venv broke silently on directory rename
- Renamed `~/xdr-project` to `~/ai-enhanced-xdr`. `start_all.sh` derives its own root from `$BASH_SOURCE`, so it survived; the virtualenv did not.
- Every script in `ml-venv/bin/` carries an absolute shebang (`#!/home/magi/xdr-project/ml-venv/bin/python3`) and `pyvenv.cfg` records the creation path. 14 files affected.
- A grep over `*.py` and `*.sh` reported no hardcoded paths and was wrong — venv console scripts have no file extension and were never matched.
- **Fix:** rewrote the path across `ml-venv/bin/*` and `pyvenv.cfg`. `python -m venv --clear` would achieve the same and is the more reliable habit.

### Entry 21 — Console: invalid icon names, wrong spacer color, unvalidated palette
- Three `iconType` values do not exist in EUI 119: `visBarHorizontal`, `visBarVerticalStacked`, `securitySignal`. EUI renders a placeholder for unknown types, which appeared as a broken-image glyph *inside empty-state panels only* — so it surfaced exactly where a chart had no data, and read as two unrelated bugs rather than one.
- All three bar charts hardcoded `stroke: "#1a1a19"` as the inter-bar spacer, but the EUI Borealis dark surface is `#0B1628` (navy). The separator was the wrong color in the only mode in use.
- Palette re-validated against each surface. The existing rule/AI pair passed colorblind separation (worst adjacent ΔE 13.0), but `#bd271e` scored **2.99:1 contrast — below the 3:1 floor**, which is why high-severity badges read as muddy rather than urgent.
- **Changes:** rule alerts `#c17e15` → `#d95926` (mustard against navy is a complementary clash), high severity `#bd271e` → `#e66767`, AI teal `#0ca58c` unchanged. Light mode was given independently validated steps rather than an automatic flip of dark. Palette is now centralised in `src/theme/palette.js`, with light/dark modes wired through `src/theme/ThemeProvider.jsx`.

### Note — detection plane moved off root; project relocated
- Everything now runs as `magi` (added to the `docker` group). The producer no longer requires `sudo docker`, closing the item recorded in the earlier `/root` permissions note.
- Project path is `~/ai-enhanced-xdr`. Kafka's compose file moved from `/root/ai-stack/` into the repository; volume `ai-stack_kafka_data` was preserved because the Compose project name derives from the parent directory name, which did not change.
- The Wazuh stack still runs from `~/wazuh-docker/single-node` (project `single-node`). Moving it into the repo would resolve to project `wazuh` and therefore to different volumes, silently discarding every indexed alert and AI detection. **Left in place deliberately** — this is a trap worth stating in บทที่ 5.
- Datasets recovered from `/root` (`archive_18.json`, windowed CSVs, run logs) now live in `~/root-backup/`, outside the repo so they are not committed. `scripts/*.py` and `dashboard/writeback.py` were repointed.

### Note — the 34 AI detections predate enrichment
- Detections from the overnight run carry no `category` and no `top_srcips`; both fields were added after that run. The category chart is therefore empty at every available time range, and the detections themselves (2026-07-19) fall outside even the 30-day window.
- Not a defect: `detection_consumer.py` writes both fields at lines 169/188. But **the enrichment path has never been observed producing output**, and confirming it requires a fresh traffic run. Until then the category feature is claimed, not demonstrated.

### Note — credentials moved to .env; VM switched to bridged networking (2026-09-07)
- OpenSearch credentials (`admin`/`SecretPassword`) moved out of source into `dashboard/.env` across `dashboard/writeback.py`, `dashboard/test_connection.py`, and `ai-stack/pipeline/detection_consumer.py` (the consumer loads it via `load_dotenv(parents[2]/"dashboard"/".env")` since it lives outside `dashboard/`). `grep` over tracked source no longer returns the password. This resolves the security-debt item carried since Entry 19.
- VM network adapter switched from VMware **NAT** to **bridged**; the VM now holds a routable LAN address (was `192.168.218.131` on the NAT subnet, now `192.168.1.142` via DHCP — a bridged DHCP lease can change on reboot, so a static reservation is worth setting before the traffic run). `ufw` is active; allow `22/tcp` (and `80/tcp` for the web lane) so incoming attack traffic from a second host is not dropped. This unblocks the fresh-traffic run — real off-host `srcip` values, the first enriched AI detections, and a demonstrable Block IP.

---

## PHASE: Web detection lane (2026-09-09)

### Entry 22 — Web detector brought online; auth/web lane-leak found and fixed
- **Brought the web lane online.** Apache on :80 → agent `<localfile>` on `/var/log/apache2/access.log` → manager → archive → Kafka → `web_detection_consumer.py` (rule 100002, pipeline `web-streaming`). Validated live against an off-host attacker (Kali via KVM NAT, real srcip `192.168.1.133`):
  - **Content-discovery scan** (gobuster, ~3152 requests): flagged `score −0.85, request_count 3152, distinct_urls 3152, error_ratio 0.999` — the model collapsed a 3000+ request scan into **one** detection.
  - **Path-traversal** curls (07:34): correctly categorised `path_traversal` / T1083.
- **Finding — the two lanes leaked into each other (silently wrong, thesis-relevant).** `detection_consumer.py` kept any event carrying `data.srcip`, on the comment's assumption that "only authentication-relevant events carry srcip." That is false — Apache access events carry `srcip` too. So the web scan was **also ingested by the auth detector** and flagged as `brute_force` (rule 100001, 3152 events, same window). This silently violated the coherent-slice separation the project's design depends on, and was invisible until web traffic actually ran through — the same failure shape as Entry 9 (`distinct_users=0`): a filter that *reads* as correct but is quietly wrong.
  - **Fix:** the auth ingest now skips events that carry `data.url` (i.e. web access events): `if "srcip" not in data or "url" in data: return`. The web consumer already keys on `data.url`, so the lanes are now cleanly disjoint.
- **Secondary — categorisation mis-priority.** `categorize()` tested the injection regex before the aggregate scan shape, so the content-discovery scan (whose wordlist happened to contain an injection-like path) was labelled `web_injection` instead of `content_discovery`. The *detection* was correct; only the label was wrong. Reordered to classify by dominant aggregate behaviour (content_discovery / vulnerability_scan / brute_force) **before** the payload-pattern flags (injection / traversal), which are for low-volume targeted requests.
- **Lesson for บทที่ 5:** a data filter or label that reads as correct within one data domain can be silently wrong across domains; only running the *other* domain's traffic through the shared pipeline exposed it. Reinforces the project's central point — invisible-to-inspection failures surface only under test.

## PHASE: Deployment on the SIAM H100 VM (2026-09-09)

Bringing the stack up on the sponsor's Ubuntu 24.04 H100 box surfaced a series of
environment gotchas — none in our code, all in the deployment substrate. Recorded
because "deploy the same containers on real hardware" is rarely as clean as it sounds.

### Entry 23 — Docker filled a 10 GB `/var` while 3.3 TB sat idle on `/`
- Image pulls failed with `no space left on device` despite `df /` showing 3.2 TB free. The enterprise image put `/var` on its own 9.8 GB LV, and Docker stores under `/var/lib/docker`.
- Moving Docker's `data-root` to `/docker` (on `/`) was **not enough** — Docker 29 uses the **containerd image store** at `/var/lib/containerd`, a separate dir still on `/var` (tell: `Storage Driver: overlayfs`).
- **Fix:** `data-root=/docker` **and** `features.containerd-snapshotter=false` in `/etc/docker/daemon.json` (reverting to the `overlay2` graphdriver under the big volume), wipe the stale `/var/lib/containerd`, restart. Merged the keys into the existing daemon.json so the nvidia runtime survived.
- **Lesson:** check where *both* Docker and containerd store data; a separate small `/var` is a common enterprise-image trap.

### Entry 24 — Cloned config files unreadable by the container (umask 0027)
- Indexer + dashboard crash-looped: `AccessDeniedException: /usr/share/wazuh-indexer/config/opensearch.yml`. The repo was cloned under `umask 0027`, so config files were mode `-rw-r-----` — the container's UID 1000 (neither owner nor group) couldn't read them.
- **Fix:** `chmod -R a+rX config/`.
- **Lesson:** bind-mounted config from a fresh clone must be readable by the container's UID; a restrictive umask silently breaks it.

### Entry 25 — requirements.txt was incomplete (worked locally, failed on a clean clone)
- Every pipeline/API process exited on `ModuleNotFoundError: dotenv`, then `httpx`. Both had been `pip install`ed ad-hoc in the local venv and were never added to `requirements.txt`, so a fresh clone lacked them.
- **Fix:** added `python-dotenv` and `httpx` to `requirements.txt` (torch stays a separate optional install).
- **Lesson:** a requirements file is only trustworthy if a clean-clone install has been tested; ad-hoc `pip install`s in a working venv hide the gap.

### Entry 26 — Password change silently broke alert shipping (AI path masked it)
- After changing the indexer admin password, the dashboard showed no new alerts and `wazuh-alerts-*` stayed frozen at 186 — yet the AI pipeline kept flagging events normally.
- **Cause:** the password was updated on the indexer (internal_users + securityadmin) but **not** in the manager's `INDEXER_PASSWORD` env, so the manager's **Filebeat could no longer authenticate** to ship alerts. The AI path was unaffected because it reads the **archive**, not the index — so alerting broke invisibly while detection appeared healthy.
- **Fix:** update `INDEXER_PASSWORD` in both compose services and recreate manager + dashboard; Filebeat re-authenticated and backfilled (186 → 493, the `rule 5710` alerts appeared).
- **Lesson (บทที่ 5):** an OpenSearch password rotation must update *every* client credential (Filebeat, dashboard), or alerting fails silently. This is a live instance of the project's own thesis — a failure invisible to the surface (dashboard looked "quiet", AI looked fine) and only caught by querying the index directly.

### Note — GPU compute blocked on the SIAM VM (see memory: siam-gpu-fabric-blocker)
- `nvidia-smi` and `--gpus all` containers see the H100, but CUDA won't initialise (Error 802, Fabric State "In Progress"); Fabric Manager can't run (no NVSwitch) and there's no IMEX service. Provider-side passthrough issue, ticket raised. CPU pipeline unaffected; GPU components (Morpheus, LLM, autoencoder-on-GPU) pending the fix.

## PHASE: GPU unblocked — LLM explainer and GPU inference (2026-10-10)

### Entry 27 — The CUDA blocker was provider-side after all (resolved, 31 days)
- Entry 23's note recorded CUDA Error 802 with GPU Fabric State "In Progress" and judged it a provider-side passthrough fault, not something fixable in the guest. A ticket was raised 2026-09-09. SIAM resolved it; confirmed working 2026-10-10: Fabric State now reports `N/A` (i.e. not applicable for this single-GPU passthrough, rather than pending), `torch 2.11.0+cu128` returns `cuda.is_available() == True`, and `docker run --gpus all` reaches the device.
- **Lesson:** the diagnosis that mattered was *whose layer the fault is on*, not what the fix was. Having established the guest could not resolve it, the correct action was a precise ticket (symptom, expected state, what was ruled out) and then working CPU-side for a month rather than guessing at driver reinstalls. The cost of being wrong about that attribution would have been a damaged driver stack on a shared box; the cost of being right was a 31-day wait during which every CPU-satisfiable deliverable was finished.
- **Still blocked: the BlueField-3 DPU.** The card *is* provisioned, but unusable — `rshim`, the host-side driver that exposes the DPU's ARM complex for management (`/dev/rshim0`), is broken, so the DPU cannot be reached to deploy anything onto it. Same category of fault as the CUDA one: the provider's layer, not the guest's. Second ticket warranted.
- Consequence for the plan: the network lane is **deferred rather than substituted**, pending that fix. If it is not resolved in time, the fallback is a software sensor (Suricata/Zeek on the host) emitting the same EVE-JSON records, with the honest cost stated — no hardware offload, so no claim to line-rate inspection.

### Entry 28 — Ollama crashed on load: a 131072-token default context, not a GPU fault
- `ollama run gemma3:12b` failed with `CUDA error: unspecified launch failure` at model warmup — alarming immediately after a month-long CUDA outage, and the obvious reading was that the GPU was still broken.
- It was not. The log showed the model loading *successfully*: `offloaded 49/49 layers to GPU`, `CUDA0 KV buffer size = 8192.00 MiB` allocated without error. Allocation working but the first kernel launch failing is a different class of fault from a dead CUDA context — and `torch` had already proven the device healthy minutes earlier.
- Cause: Ollama defaulted to the model's full `n_ctx = 131072`, reserving an 8.8 GB KV cache and building a 1927-node graph that failed to launch. `OLLAMA_CONTEXT_LENGTH=4096` fixed it outright. Flash Attention was suspected first and exonerated — re-enabling it with the smaller context works fine.
- **Fix:** systemd drop-in at `/etc/systemd/system/ollama.service.d/override.conf` setting `OLLAMA_CONTEXT_LENGTH=4096`. Ample for 2–3 sentence explanations.
- **Lesson:** a CUDA error does not imply a CUDA problem. Read *how far* the process got — successful device allocation followed by a launch failure points at the workload's shape, not the hardware. Also: the first thing tried (disabling Flash Attention) appeared to work only because the same command changed two variables at once; isolating them afterwards is what identified the real cause.

### Entry 29 — `/home` is a 9.8 GB volume too (the Entry 23 trap, second instance)
- Running `ollama serve` as `saiuser` instead of via systemd moved the model store from `/usr/share/ollama/.ollama` (on `/`, 3.1 TB free) to `~/.ollama` — and `/home` is its own 9.8 GB LV on this image. A 7.3 GB pull filled it to **100%, 0 bytes free**.
- **Fix:** deleted the partial blob and went back to the systemd service, configuring it by drop-in rather than by running the daemon by hand.
- **Lesson:** the same partition trap as Entry 23, reached from a different direction — on this image only `/` is large, and *any* path under `/home`, `/var`, or `/tmp` is on a ~10 GB volume. Check `df -h` before writing anything multi-gigabyte, and prefer configuring a service over re-running it as yourself, since the service account's paths are part of its configuration.

### Entry 30 — pip's temp and cache directories are on the small volumes too (Entry 29, third instance)
- Installing Morpheus's pip requirements died at 596/665 MB of the `nvidia-cudnn-cu12` wheel with `OSError: [Errno 28] No space left on device`, despite the conda env itself living on the 3.1 TB volume.
- pip unpacks wheels under `$TMPDIR` (`/tmp`, 4.9 GB) and caches downloads in `~/.cache/pip` (`/home`, ~4 GB free). A torch build pulling ~2.5 GB of CUDA wheels exhausts either.
- **Fix:** `export TMPDIR=/LuckyFive/tmp PIP_CACHE_DIR=/LuckyFive/pip-cache` (both on `/`), after clearing the partial cache.
- **Lesson:** the third separate outage from the same root cause (Entries 23, 29). Installing a package is not one destination but three — the environment, a staging directory, and a cache — and on this image only `/` can hold any of them. The durable fix is to set those paths once in the shell profile rather than rediscover it per tool; recorded in SETUP.md so the next person does not pay for it a fourth time.

### Entry 31 — Blocked by the other group's stack; host ports ignore project namespacing
- Attempting the end-to-end run found 9200, 9201, 9092, 1514, 1515, 55000 and 8443 already bound by the other group's containers (`edrxdr-*`, project `wazuh`), left running for three days. Our own stack could not start.
- The project had assumed `-p luckyfive_wazuh` provided isolation. It does not: compose project names scope *container and volume names*, never host port bindings, which bind once per host.
- Worse than a failure to start: `localhost:9092` was **hardcoded** in three pipeline files. With their broker on 9092 and ours absent, the producer would have published into *their* Kafka — a cross-contamination that no error message would have reported.
- **Fix:** every host port moved into compose variables (`wazuh/.env`, `ai-stack/.env`) with the current values as defaults, so nothing changes on a machine you own; `KAFKA_BOOTSTRAP` added to the pipeline and **printed in each consumer's startup banner**, so the broker in use is always visible. Documented as SETUP.md §0 with a known-free port set.
- **Lesson:** the instinct was to stop their containers. Their `edrxdr-replay-*` containers had been up 39-40 hours — an evaluation run, the same kind this project ran overnight in August. Shared infrastructure makes "just restart it" someone else's lost dataset. Being *configurable* is the durable answer: it removed the dependency on their schedule entirely, and took twenty minutes.

### Entry 32 — Scope decision: the DPU network lane is out of scope (2026-10-17)
- Confirmed that the BlueField-3 DPU network lane falls outside this project's scope. It had been carried as "Phase 2 (committed)" in `project_plan.md` Step 10 and as "deferred pending a provider fix" in Entry 27; the `rshim` fault was never resolved, so nothing was built for it.
- **Decision:** dropped, not substituted — the software fallback recorded in Entry 27 (Suricata/Zeek on the host) is not pursued either. Docs that promised the lane (README, SETUP, ROADMAP, project plan) now say out of scope; Entries 18 and 27 are left as written, since they record what was true at the time.
- **Consequence:** both detection lanes (auth, web) read endpoint logs, so coverage is across log sources on the host, not across layers (endpoint + network). Stated as Known limitation 6 in `results_log.md`.

### Entry 33 — Our agent had been reporting to the other group's manager for a week (2026-10-18)
- The console's Agents page showed the VM's agent (id 003) **disconnected since 2026-10-11 13:37**, while SSH-based AI detections kept arriving — so nothing looked broken on the detection side.
- Cause: on 10-11 our manager moved to host ports 1516/1517 (Entry 31), but the VM's agent (`/var/ossec/etc/ossec.conf`) still dialed **1514** — the other group's manager. `ss -tnp` showed `wazuh-agentd` with an **established** connection to `127.0.0.1:1514`, and its log was clean (scans running, no connection errors): it was working, just for the other stack.
- Why detection never noticed: our manager reads the host's `auth.log` directly (a bind mount, `host_auth.log`), so the SSH lane never depended on the agent. What *was* lost: Block IP (Active Response runs on the agent), FIM / rootcheck / SCA / inventory for the host.
- **Decision:** leave the host agent with the other group (one machine runs one native agent; one agent reports to one manager — re-pointing it would silently cut them off) and run **our own agent in a container** (`wazuh.agent` in `wazuh/docker-compose.yml`, SETUP §3b): enrolls on 1517 as `luckyfive-agent`, host networking + `NET_ADMIN` so blocks land in the VM's firewall, Active Response only.
- **Lesson:** Entry 31 again, one layer down — a shared host's *agent* is shared infrastructure just like its ports, and a component can be fully healthy while serving the wrong owner. The signal was in our own console (Agents: disconnected) a week before anyone looked; the Pipeline page added in batch 4 now surfaces this class of thing next to the detectors.

### Entry 34 — Decision: Filebeat replaces the Python producer for Wazuh → Kafka (2026-10-18)
- `archive_producer.py` ran `docker exec <manager> tail -F -n 0` on the archive. `-n 0` means "new lines from now on": anything Wazuh wrote while the producer was down (crash, restart, reboot) never reached Kafka — a silent gap in what the AI saw.
- **Decision:** a second Filebeat instance (`ai-stack/filebeat/filebeat.yml`, a service in `ai-stack.yml`) reads the manager's log volume read-only and ships each archive line to Kafka unchanged. It records its read position (registry), so it catches up after downtime; its first-ever start begins at the end of the file, as the producer did. The volume is named explicitly, so on the shared VM it can only read *our* manager.
- **Why a second Filebeat, not the built-in one:** Filebeat has one output, and the manager's own already ships rule alerts to the indexer. This is the "production equivalent" the producer's docstring always named, and it matches the original proposal (Figure 3.1: Filebeat → Kafka) — one divergence from the proposal removed (`sad_diagrams_chapter3.md`).
- Consumers now drop an undecodable line instead of crashing (`decode_event`). `archive_producer.py` is kept only as a manual fallback until Filebeat has run on the VM for a while. Verified on the VM 2026-10-21: a raw `host_auth.log` event read back from the Kafka topic.

### Entry 35 — Decision: everything after Wazuh runs as containers; `start_all.sh` removed (2026-10-18, verified 2026-10-21)
- The API and both detectors ran as `nohup` processes from `start_all.sh`, which never stopped old ones. That caused a real fault: a stale `uvicorn` kept serving old code (JSON "Not Found", filters ignored) until killed by hand. Nothing restarted a crashed detector, and logs were scattered in `logs/*.log`.
- **Decision:** one image (repo-root `Dockerfile`: the console is built with Node inside it, then Python + `requirements.txt`) runs three services in `ai-stack.yml` — `api`, `auth-detector`, `web-detector` — next to Kafka and Filebeat. Host networking (so every address in `dashboard/.env` works unchanged), `.env` bind-mounted read-only (never baked into the image), `restart: unless-stopped`, capped logs, and an API healthcheck. One command starts everything after Wazuh; `npm run dev` is now only for frontend editing.
- **Consequence:** the image has no PyTorch, so the containers run Isolation Forest. The VM's `.env` had `DETECTOR_MODEL=autoencoder`, which would have crash-looped at the first scoring; switched to `isolation_forest`. The GPU models return with the Morpheus container.
- **Verified on the VM (2026-10-21):** image built, console served from the `api` container on :8000, both detectors reporting heartbeats (`warming up`), auth windows filling from live events.
- **Lesson:** "it's just a script" was not the problem — Python is fine in production. *How* processes are run is what made the setup fragile; supervised containers fixed the stale-process fault class rather than that one instance.

### Entry 36 — Decision: datasets and evaluation protocol (2026-10-21)
- The detectors refit every minute on a rolling buffer with contamination 0.15, so they **always flag ~15% of windows**, attack or not. An evaluation of that mode measures the contamination setting, not the model. **Decision:** add a train-once mode for evaluation — fit on normal-only data, freeze the threshold on a normal validation period, then score the test period.
- **Primary dataset: AIT-LDS v2.0** (scenarios russellmitchell + fox, santos if time). It is the only public dataset found that has, for *both* lanes, raw Apache access + Linux auth logs with real timestamps and IPs, attack-free days to train on, and line-level labels. Peer-reviewed (IEEE TDSC 2023); its authors also replayed it through Wazuh (AIT-ADS), a reference for AI vs rules.
- **Required second test set: our own scripted lab attacks** with a schedule file (time + attacker IP). AIT has no SSH brute force or spraying, and no SQLi/XSS, so those attack types can only come from the lab.
- **Rejected, and why (format, not reputation):** CIC-IDS2017/2018 — network flows, host logs unlabelled, documented labelling artefacts; LANL — Windows/AD auth, no sshd lines or IPs; CSIC 2010 — no timestamps, so no time windows; LogHub OpenSSH / SecRepo — no labels; honeypots — no normal traffic; SR-BH 2020 — no clean normal period.
- **Protocol:** chronological split (train days 1–2, threshold on day 3, test the attack day); a window is positive if it contains ≥1 labelled line; one threshold rule for all models (IF, autoencoder, Morpheus DFP); PR-AUC + false alarms per day, not accuracy (attacks ≈ 1% of windows); recall per attack type; baselines: Wazuh rules **and** a trivial count threshold; ablations without `hour` and without `max_rule_level`; no point-adjust scoring.
- Full comparison, sources and an examiner Q&A: `docs/dataset_selection.md`.

### Entry 37 — Scope decisions for the final weeks (2026-10-21)
- **Web lane kept, not wired on the VM.** The VM's manager reads only the host `auth.log`, so the live web detector receives nothing (shows 0/10 windows). Its live evidence is R11 (earlier setup: ~3000 rule alerts → 1 AI detection, real attacker IP), and its evaluation runs offline on AIT access logs and lab captures. Wiring a web server's log into the VM's manager is a demo-prep item, only if time allows.
- **Two lanes are enough.** Adding a surface is cheap to ingest (a `<localfile>` + a decoder) but a new detector, feature set and evaluation each time; further surfaces (DNS, `sudo`, FIM) are future work.
- **Out of scope:** user accounts / RBAC / SSO, HTTPS, separate VMs per tier — documented in `docs/security.md` as limitations with the production answer, not built.
- **Order:** datasets and evaluation before the Morpheus runtime container — the results chapter is the riskiest deliverable, and the evaluation already covers DFP as a model. VM access ends 30 Nov; VM work to finish by ~25 Nov.

### Entry 38 — AIT-LDS evaluates the web lane only; one feature definition for live and offline (2026-10-21)
- Inspected AIT-LDS v2.1 russellmitchell (the `_no-pcaps` zips added in April 2026: 0.5–0.7 GB per scenario instead of 7–16 GB; same data and labels as v2.0). The attacked host's `auth.log` holds ~630 lines in four days — ~600 of them CRON, **5 sshd lines with a source IP** — and the attack reaches it only as 8 `su`/`sudo` lines by `www-data`. The SSH lane watches remote logins, so on AIT it would see almost nothing.
- **Decision:** AIT-LDS is used for the **web lane** (the intranet server's Apache access logs: 11,130 requests, 4 attack minutes — service scan, dirb 4,687 requests, WPScan + webshell upload, webshell commands — all from one attacker IP); the **SSH lane is evaluated on lab data only**. Refines Entry 36.
- **Same features by construction:** the window/feature code moved out of the two consumers into `ai-stack/pipeline/features.py`, used by the live detectors and by the offline loader (`scripts/ait_windows.py`). Verified: old vs new consumers produce identical feature frames on 3,000 synthetic Wazuh events; the models' live `fit_score` output is byte-identical.
- **Train-once mode** added to all three model wrappers (`fit` / `score`), and `scripts/evaluate.py` implements the Entry 36 protocol (chronological split, validation-percentile thresholds, PR-AUC, false alarms/day, per-step recall, count baseline, no-`hour` ablation).
- **First local result (russellmitchell, CPU, IF + autoencoder):** every model detects the attack within one minute at ~1–3 false alarms/day — **and so does a plain request-count threshold, with zero false alarms**: AIT's scan is loud enough that volume alone finds it (the Arp et al. warning, Entry 36). The quiet attack minutes (4 and 14 requests at 03:56 / 03:59) are caught only through the `hour` feature, and only sometimes. Both are findings to report, not to tune away; the lab's quieter attacks are where the models must earn their place over the count rule.

### Entry 39 — Lab baseline generator (2026-10-21)
- The SSH lane has no public labelled data (Entry 38), so it is evaluated on our own lab, which needs a clean "normal" baseline to train on before any attack. Built `lab/baseline/lab_baseline.py`: a pure-stdlib generator that writes genuine-format `auth.log` (RFC3339 sshd + PAM + CRON) and `access.log` (Apache combined) with per-employee source IPs in 10.20.0.0/24 (retires the 127.0.0.1-only limit, results_log 5.3), a work-hours rhythm (UTC, aligned to AIT so the two are comparable), a nightly backup login and a fixed-cadence monitoring login (benign off-hours + steady SSH so the model does not learn that all quiet-hour SSH is anomalous), and the occasional mistyped password. It writes log files only — no real connections — so "synthetic normal, optimistic false-alarm rate" is a stated caveat (Arp et al.; AIT's normal is simulated too).
- Two modes from one generator (identical content per `--seed`): `realtime` (append a minute at a time, run ~3 days) and `simulate` (fast-forward N days at once). Containerised in `lab/docker-compose.yml` (`restart: unless-stopped`, writes to `/LuckyFive/lab/logs`), separate from `ai-stack.yml` on purpose.
- **Verified on this PC** (no Docker needed for the generator): 3 simulated days → 95 auth windows over 5 source IPs and 308 web windows (~300 req/day, request_count ~3, error_ratio ~0.01 — matching AIT's normal web shape); same seed is byte-identical, different seed differs; realtime appends live and stops cleanly on SIGTERM (`docker stop`). Built with the live detectors' own `features.py`, so lab and AIT windows are the same feature space.
- **Not built yet (next):** `lab/attacker/` (brute force, spraying, slow/low, distributed, web scans/SQLi/XSS → `attack_schedule.csv`) and a lab loader (`auth.log`/`access.log` + schedule → labelled windows for `scripts/evaluate.py`). The authoritative run also replays the lab logs through Wazuh for genuine rule levels and the rule baseline.

## BUILD STATUS (last updated: 2026-10-10 — GPU unblocked; LLM explainer live; Morpheus in the slot)
- **Steps 1–3 COMPLETE:** Ubuntu 26.04 VM (VMware) → Docker → Wazuh stack running, dashboard verified, `logall_json: yes`, `archives.json` populating. Snapshot: `wazuh-stack-running`. **Now operating as `magi`** (docker group), not root; project lives at `~/ai-enhanced-xdr`, Wazuh stack at `~/wazuh-docker/single-node`.
- **Step 4 COMPLETE (mock) / PARTIAL (real):**
  - Mock: Isolation Forest caught 5/5 planted anomalies, ~1% FPR, CPU. Claim B on controlled labelled data.
  - Real: SSH server + Wazuh agent (`ubuntu-vm`) deployed and Active; endpoint → agent → manager → decode → `archives.json` proven; feature engineering working (JSON → windowed features). One genuine model-only detection at 05:32 + one acknowledged false positive.
- **OVERNIGHT EVALUATION COMPLETE:** ~7.5 h run, 4,057 events, three attack episodes at 3 s / 30 s / 75 s spacing with independent ground-truth timestamps. **Rules detected episodes 1 and 2 (2 alerts each) and produced zero alerts for episode 3; the model produced detections in all three.** 34 AI detections written. This is the headline result (R10).
- **Step 8 SAD diagrams COMPLETE:** Context Diagram, DFD Level 1, Data Dictionary, and State Diagram written as Mermaid source in `docs/sad_diagrams_chapter3.md`, describing the system as built with divergences from the proposal noted. This closes what was previously the largest documentation gap.
- **HARDWARE PROVISIONED (see Entry 18):** SIAM AI H100 80GB + BlueField-3 DPU VM available 2 Sep – 30 Nov 2026. Morpheus and the local LLM move from "documented target" to actual deployment targets; the DPU network lane was later ruled out of scope (Entry 32). Not yet accessed — VPN/SSH onboarding is the next hardware step.
- **Results banked for บทที่ 4:** (1) mock IF 5/5 @ ~1% FPR; (2) **R10 — detection degradation by attack speed, ground-truth verified**; (3) alert reduction (384 rule alerts → 5 model detections in the earlier session); (4) anomaly *scores* provide ranking, not binary thresholds; (5) live streaming pipeline demonstrated end-to-end.
- **KNOWN DATA LIMITATIONS (state in บทที่ 5):** single-host lab data, one source IP (127.0.0.1 — `srcip` unusable as a feature), single monitored endpoint, episode-3 detections are weak-signal, host suspension created a ~3 h baseline gap.
- **REMAINING WORK:**
  1. **Fresh traffic run from a second host** — bridged networking is now in place; attack from the host machine over the LAN. This single run unblocks three things at once: real `srcip` values (loopback is refused by the block-ip guardrail, so Block IP is currently undemonstrable), the first AI detections carrying `category`/`top_srcips`, and a non-empty console. See the enrichment note above.
  2. **Web detector on Apache :80 — DONE (2026-09-09).** Online and validated: a content-discovery scan from a real off-host IP was collapsed to one detection (rule 100002); path traversal also caught. See Entry 22 (includes the auth/web lane-leak fix).
  3. **Write up บทที่ 4 and 5** from `results_log.md` and this file. Raw material is complete; the prose is not written. SAD source for บทที่ 3 is now done (`sad_diagrams_chapter3.md`).
  4. **Local LLM alert explanation** — now deployable on the provided H100 (vLLM + a 20–70B model), on-demand. SIAM goal #3.
  5. **Autoencoder** — model step-up, comparison against Isolation Forest.
  6. **DPU network lane — out of scope** (decided 2026-10-17, Entry 32). Not built; no software substitute.
  7. Optional: multi-scale windowing analysis (1 / 5 / 15 min) on the overnight dataset — the data now supports it and it directly addresses the slow-attack question.
- **Security debt outstanding:** OpenSearch credentials are now in `dashboard/.env` (resolved). Remaining: the stale July cert copy under `wazuh/config/wazuh_indexer_ssl_certs/` is dead since regeneration and should be deleted so there is one source of truth.
- **Fixes to apply before any future unattended run:** `python -u` for the consumer (unbuffered logging); disable host sleep; randomise attack times/intensities rather than repeating a fixed schedule.
