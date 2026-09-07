# AI-Enhanced XDR — Complete Working Plan

*A single reference pulling together the whole plan: pipeline, tools, how they interconnect, what's missing, document structure, and the order to actually do things.*

> **How to read this:** This is base knowledge to work from, not gospel. Verify specifics (exact configs, versions, your course's report template) against official docs and your advisor. The *reasoning* and *sequence* here are sound; treat exact commands/settings as "look them up when you get there."

---

## PART 0 — The one-sentence scope (your flag)

> **"Wazuh catches known attacks with rules. My AI catches anomalies rules miss — deviations from normal in system activity, not tied to pre-defined signatures. I show both on a dashboard, tagged separately. Everything else = future work."**

Everything below serves that sentence. When unsure whether to add something, ask: *does it help prove that sentence?* If no → it's future work, write one line about it, move on.

**Critical distinction — where the "generality" lives:** Your AI's *capability* is general anomaly detection (any deviation from normal, not just specific attacks). But you *demonstrate* it on ONE coherent data type at a time — NOT by mixing every activity type into one model. The generality is in the **method** (an autoencoder/isolation forest learns "normal" for whatever you feed it, so it's inherently more general than rules), not in juggling logins + network + files + HTTP all at once.

Why this matters (answers "would it be too many features?"): each activity type has totally different features — login data has time/IP/user; network data has packet-size/port/protocol/duration; file data has others again. Cramming them all into one model = a feature soup the model can't learn from. That's the real "too many features" failure — **incoherent** features mashed together, not just "a lot." Many *related* features within one data type = totally fine (network flow data legitimately has 80+ features and models handle it). Many *unrelated* features across types in one model = broken.

**So:** broad claim in the writeup ("general anomaly detection across system activity"), coherent demonstration in practice (prove it on one dataset at a time). This also happens to match your hardware limit perfectly — see Part 4 / testing.

**Two claims that make "done" reachable:**
- **Claim A — the plumbing works:** data flows Endpoint → Wazuh → Kafka → OpenSearch → Dashboard. *CPU only. Mostly one-shot-able. ~70% of the project, and it's the easy mechanical part.*
- **Claim B — the AI adds value:** an anomaly model flags deviations from normal that rules miss (demonstrated on one coherent dataset). *Runs standalone on CPU. Iterative by nature. Small and isolated.*

Keep these mentally separate. They're proven differently and they fail differently.

---

## PART 1 — The pipeline, tool by tool

### The flow (two parallel paths)

```
                          ┌─ alerts.json ──→ Filebeat ──→ OpenSearch ──→ Dashboard
Endpoint → Wazuh Agent →  │                  (rule hits)                    ▲   (fast path, always works,
   (1514)      Manager    │                                                 │    no AI dependency)
             (analysisd)  │                                                 │
                          └─ archives.json → Filebeat ──→ Kafka ──→ ML consumer
                             (ALL events,                            (anomaly detection)
                              logall_json:yes)                            │
                                                              anomaly? → writeback ─┘
                                                              (tag: source=ai, rule id 100000+)
```

### What each tool does and why it's there

**Endpoint + Wazuh Agent**
- *Job:* collect on the endpoint (logs, file integrity, process, inventory), forward to manager.
- *Only path is Agent → Manager over port 1514, encrypted. Not reroutable.* Agent does NOT parse or apply rules — it just collects and ships.
- Two axes of data to keep straight:
  - **Axis A (how it collects / modules):** Log collection, FIM, Inventory (Syscollector), SCA, Vuln, Rootcheck. Finite, ~6 modules.
  - **Axis B (what the data is about):** auth/login, network, HTTP, DNS, process, file… Unlimited, depends what logs you feed it. **This is the axis that matters for the AI.** Your AI *method* is general (works on any of these), but you *demonstrate* on one coherent slice at a time — don't mix slices into one model. Pick the slice per experiment (e.g. auth data for login anomalies, OR network-flow data for network anomalies).

**Wazuh Manager (analysisd is the brain)**
- *Job:* decode raw events into structured fields, run them through rules, output alerts.
- Two outputs, and **the distinction is the single most important technical point in this project:**
  - `alerts.json` — ONLY events that matched a rule.
  - `archives.json` — EVERY event, matched or not. **Requires `logall_json: yes` in config (off by default).**
- **The AI MUST consume `archives.json`, not `alerts.json`.** If it reads alerts.json it only ever sees what rules already caught → it can never catch what rules miss → the entire project's point collapses. This is the easiest thing to get wrong. Burn it in.

**Filebeat**
- *Job:* tail a file, ship its contents onward. No logic, no parsing — just a file-tailer + shipper.
- Not opening a listening port; it pushes outward.
- Not philosophically mandatory (Logstash/Fluentd/custom could replace it) but **practically yes, keep it** — it's what every Wazuh setup uses, path of least resistance. Don't fight it to avoid it.
- In this design it does two ships: alerts.json → OpenSearch, and archives.json → Kafka.

**Kafka**
- *Job:* buffer + fork point. Decouples producers from consumers.
- *Why it earns its place for YOU specifically:* when the ML/GPU part is slow or down, Kafka buffers events in a queue instead of dropping them, and **the fast path (→ OpenSearch → Dashboard) never notices.** This is what makes the two paths independent.
- Use **KRaft mode** (modern Kafka) to drop Zookeeper → one less memory-hungry process. (RAM matters, see Part 4.)

**The ML consumer (this is "Morpheus" conceptually)**
- *Job:* read events from Kafka, run anomaly detection, flag deviations from normal.
- **Key realization: Morpheus is just a container/wrapper over ML that makes it run fast on GPU at scale. The ML is the substance.** You do NOT need Morpheus to prove the concept.
- **Start it as a dummy stub** — a Python consumer that reads a Kafka message and prints / POSTs a fake alert. This alone proves the whole architecture end-to-end with zero ML. Huge early milestone.
- Then swap the stub's guts for real detection: **Isolation Forest (scikit-learn) or Autoencoder (PyTorch)** on your chosen dataset's features. Both run on CPU for small data. Remember: general *method*, but train/test on one coherent data slice per experiment — don't feed mixed data types into one model.

**Triton (if you use real Morpheus)**
- *Job:* model server. **It is a SERVICE the ML calls (request→response), NOT a stage data flows through.** Draw it hanging off the ML box, not inline in the pipe. Common diagram mistake.

**LLM (alert explanation)**
- *Job:* rewrite a flagged alert in plain English for the analyst. **It does NOT detect anything — it's a translator/label-printer.**
- Make it **on-demand** (fires when analyst clicks "explain"), not always-on → saves enormous compute.
- The genuinely GPU-hungry bit. **Update (Sep 2026): the H100 80GB provided by SIAM AI runs a real local model** — a 70B fits in VRAM, or a 20–30B comfortably alongside everything else. No longer forced to a tiny quantized model or hosted API. Still the least essential part; make it on-demand, don't let it eat the schedule.

**OpenSearch (= Wazuh Indexer)**
- *Job:* store + search + analyze events fast. It's a search engine, not a normal DB — built for logs.
- **It IS OpenSearch — "Wazuh Indexer" is just Wazuh's rebrand of it.** That's why you hadn't heard the name; it was hidden behind "indexer."
- Central store where **everything converges**: rule alerts land here, AI findings get written back here, dashboard reads from here. Necessary — no OpenSearch = nowhere to store, nothing to display.
- **Cap its heap for testing** (`-Xms1g -Xmx1g`) — it grabs a lot by default. (Only needed on the 10–12GB local VM; on the provided 224GB VM this cap is optional, though still fine to keep.)

**Dashboard**
- *Job:* display alerts, let analyst act.
- **Recommendation: build your own small one (React/Next.js)**, not Wazuh's built-in. Reason: your whole selling point is showing rule-alerts vs AI-alerts *side by side, tagged* — Wazuh's dashboard isn't built for two sources and customizing it deep is painful. A custom page reading two indexes from OpenSearch is more direct and fully controllable.
- Start ugly: a table pulling alerts from OpenSearch, tagged by source. Pretty comes later. **No GPU, easy to test in isolation, quick visible win.**

**The writeback loop (the piece that was fuzzy)**
- When the ML flags an anomaly → the finding goes **back into OpenSearch**, tagged `source=morpheus_ai`, using **Rule ID 100000+** (the correct custom-rule range in Wazuh).
- Dashboard reads both → shows AI alerts and rule alerts together, distinguishable.
- **Note:** the doc says "via Wazuh REST API" but the REST API (port 55000) is really a *management* API, not built for injecting alerts. Two honest options: (a) feed the event back into the manager so a custom rule catches it (matches your 100000+ tagging), or (b) write directly to OpenSearch matching the schema. For a custom dashboard, (b) into a separate `ai-detections-*` index the dashboard also reads is cleanest. **Fix this wording in the doc.**

---

## PART 2 — Is anything missing / wrong?

**Missing: nothing structural.** The pipeline is complete and coherent. Every component earns its place. **Do not add tools** — more surface area, more breakage, zero added proof. When in doubt, remove, don't add.

**Things to fix / watch (from the existing doc):**

1. **"Pretrained, not trained" contradiction.** The doc repeatedly says "use pretrained, don't train," but DFP and autoencoders *by nature must fit to your own data* — there is no pretrained DFP that knows your users. Pick a stance: "we use Morpheus's model architecture but fit the baseline on our data" (honest, correct) rather than "we don't train at all." Truly-pretrained Morpheus models (phishing/sensitive-info NLP) do a *different job* than login-anomaly detection.

2. **archives vs alerts** — covered above. The doc's Phase 1 correctly says `logall_json: yes` — good. Just make sure the AI actually consumes the archive, not alerts.

3. **Data type mismatch in evaluation.** Doc plans to evaluate with **CICIDS2017 (network flow data)** but the pipeline feeds Morpheus **Wazuh host logs (auth/FIM)**. These are *different data types*. Wazuh is host-based; it doesn't natively eat raw packets. Either (a) target **auth-log anomalies** (DFP) which fits Wazuh cleanly — recommended for your login flag, or (b) if you insist on CICIDS, feed its CSV features straight to the ML *offline* (bypassing Wazuh). Don't pretend PCAP flows through Wazuh archive naturally — that needs Suricata/Zeek in between. **Pick one lane and state it.**

4. **"Wazuh REST API" for writeback** — reword per Part 1's writeback note.

5. **Triton as stage vs service** — fix in the architecture diagram.

6. **Hardware — RESOLVED (Sep 2026).** This item was originally: *the doc's RTX 5070 etc. are placeholders; the real constraint is AMD RX 5700 XT (no CUDA) + 16GB RAM, so pipeline + ML run on CPU and Morpheus is a documented-but-undeployed target.* **That constraint no longer holds.** SIAM AI Cloud provisioned (2 Sep – 30 Nov 2026): an Ubuntu 24.04 VM with **14 vCPU / 224GB RAM / 3.4TB disk / 1× NVIDIA H100 80GB (passthrough) / 1× BlueField-3 DPU (passthrough)**, over VPN+SSH. Consequences: Morpheus is now *deployed*, not merely designed toward; the local LLM runs for real; CPU-only was a constraint, not a design preference, and is now lifted. The CPU implementation remains valid as the *proof-of-method* baseline and as the fallback if the GPU work runs short — keep it in the writeup as an equivalence result, not as the only option. **Caveat:** the H100 and BlueField are shared with another group on the same VM — coordinate, and don't assume exclusive GPU access. The window closes 30 Nov, so hardware-bound work is now the deadline-critical path (see Part 4).

**Things the doc does RIGHT (keep):**
- `logall_json` → archive → Filebeat (correct source for catching what rules miss).
- Tag-based dedup with Rule ID 100000+ (correct custom range).
- Two paths, AI parallel not in critical path.
- Evaluation rigor (comparison rule-only vs +AI, clear metrics/targets).
- Human-in-the-loop for low-confidence alerts.
- LLM as explainer not detector (correct scope).
- Awareness of poisoning/drift (mature — just don't over-scope it).
- "Mock Morpheus" instinct — *lean into this*, it's the load-bearing decision for no-NVIDIA-hardware.

---

## PART 3 — Document structure

*Base structure — the standard Thai 5-บท format. Confirm against your department's template; if they give one, theirs overrides this.*

- **บทที่ 1 — บทนำ:** ความเป็นมา, วัตถุประสงค์, ขอบเขต, ประโยชน์, ระยะเวลา. *(You have this.)*
- **บทที่ 2 — ทฤษฎีและงานวิจัยที่เกี่ยวข้อง:** concept definitions + related work. *(You have this. Your citations lean definitional — strengthen with a couple of "someone built a similar system" papers so you can position your gap. Search Google Scholar / arXiv for "Wazuh machine learning anomaly detection", "LLM security alert triage", and specifically "Morpheus Wazuh" — the near-emptiness of that last search IS your novelty evidence.)*
- **บทที่ 3 — วิธีดำเนินการ / การวิเคราะห์และออกแบบระบบ:** **← ALL SAD GOES HERE.** Methodology + system analysis & design. Your existing AI-Pipeline architecture figure lives here. Add: Context Diagram, DFD Level 1, State Diagram, Data Dictionary.
- **บทที่ 4 — ผลการดำเนินงาน / การพัฒนาระบบ:** implementation + results. *Where Claim A and Claim B get demonstrated with actual output/metrics.*
- **บทที่ 5 — สรุปผลและข้อเสนอแนะ:** conclusion + limitations + future work. *Where your logged failures become "lessons learned," and where "other attack types / real Morpheus at scale" become future work.*

*(Some departments split 3 into 3=design, 4=implementation, 5=results. Either way SAD stays in the design chapter.)*

### SAD artifacts — which to actually do

Standard SAD assumes a database CRUD app; yours is a pipeline, so fit varies. Rule: **do the ones that force you to understand something; skip ceremony.**

| Artifact | Do it? | Why |
|---|---|---|
| **Context Diagram (DFD Lv0)** | ✅ Yes | Forces scope clarity (whole system as 1 process + external entities). |
| **DFD Level 1** | ✅ Yes | Forces naming every process + data handoff. If you can't draw it, you don't understand your pipeline yet. Fits a pipeline perfectly. |
| **Data Dictionary** | ✅ Yes | Define your JSON event fields here. (Your "entity dictionary" — real name is data dictionary.) |
| **State Diagram** | ✅ Yes | Alert lifecycle: New → AI-enriched → Triaged → Responded/Resolved. Fits well; genuinely illuminating. **Do this AFTER seeing real alerts** — more accurate. |
| **Activity Diagram** | ⚠️ Optional | Only if response-logic flow is complex enough to be unclear otherwise. |
| **ERD** | ⚠️ Ask advisor | Pipeline barely has relational data. Don't manufacture a fake one. May be replaced by the architecture/component diagram. |
| **UI Design / wireframes** | ❌ Skip | DFDs are about data movement, not screens. Marginal for a pipeline. (Your own instinct flagged this — correct.) |
| **Use Case Diagram** | ⚠️ Optional | Light one (actor: SOC analyst; use cases: view alerts, get explanation, trigger response) if your template wants it. |

**Balancing rule (markers check this):** data flows in/out of a parent process must appear on its child diagram; each level must reconcile with the one above. Context ↔ Level 1 must match.

**The interlock (why these, not random):** Context defines scope → DFD Lv1 explodes it + reveals data stores → data stores become ERD entities → every flow/store defined in data dictionary → process internals described in process spec → state/activity capture behavior DFDs deliberately can't (DFDs have no control flow, by design). UI isn't in this chain → that's why it's skippable.

---

## PART 4 — What to do first (the actual order)

### Hardware reality

**Two environments now — keep them straight.**

**A) Local dev VM (unchanged, still useful).** Ubuntu on VMware Workstation Pro (Windows host), 4 cores / 10–12GB RAM / 80–100GB dynamic disk. This is where the project was built through Steps 1–3. Keep it as the offline dev box and the fallback if the VPN to SIAM AI is flaky. On *this* box the old RAM discipline still applies: component-by-component, cap OpenSearch heap (`-Xms1g -Xmx1g`), Kafka in KRaft, keep the LLM off it. RAM is the binding constraint here.

**B) Provided SIAM AI VM (Sep 2–Nov 30, 2026 — the deployment target).** Ubuntu 24.04, **14 vCPU / 224GB RAM / 3.4TB disk / 1× H100 80GB (passthrough) / 1× BlueField-3 DPU (passthrough)**, reached over VPN+SSH. This is where Morpheus, the real LLM, and the DPU network lane run. Notes:
  - **RAM is no longer the constraint here** — run everything at once if you want. The heap-cap and sequential-startup rules are local-VM survival tactics, not needed on this box.
  - **The H100 unblocks Morpheus and the local LLM.** Both move from "designed toward" to "deployed."
  - **The BlueField-3 is the network-lane sensor** (Suricata on the DPU → flows into Kafka). See Part 2 / Phase 2.
  - **Shared with another group on the same VM.** Isolate your work in Docker containers; pick a port range and tell the other group; never point attacks at anything outside your own containers; the H100 and DPU are shared, so coordinate and don't assume exclusive access.
  - **Egress may be locked down** — test `curl github.com` early; if blocked, `scp` datasets/models over the VPN.
  - **Back up continuously** (git push; the consent form puts data loss on you) and **the VM disappears 30 Nov** — anything that exists only there is gone then.
  - **Long jobs in `tmux`/`screen`** — a VPN drop kills a bare SSH session and whatever ran inside it.

- **Snapshot discipline (local VM):** snapshot after Ubuntu+Docker install and at each working milestone. One-click rollback beats reinstalling. (On the provided VM you may not have snapshot control — git + external backups are the equivalent there.)

### The sequence

**Step 1 — Create the VM + install Ubuntu. Today.**
Ubuntu inside VMware Workstation Pro (4 cores / 10-12GB RAM / 80-100GB dynamic disk). Linux in a VM = still real Linux — every tutorial applies; you just get snapshots as a bonus. Consider Ubuntu **Server** (no GUI, SSH in from the host) to save ~1.5-2GB RAM — you're building terminal skills anyway. Concrete, finishable, unblocks everything. **This is the literal first move — download the ISO.**
→ *Start the failure log here. Entry 1: "Setting up Ubuntu VM."*
→ *After Ubuntu + Docker are installed and working: SNAPSHOT before touching anything else.*

**Step 2 — Learn Docker by doing, not as a course.**
You need ~5 concepts: what a container is, what docker-compose does, `docker compose up`, viewing logs, stopping things. An afternoon hands-on. **Learn it by running Wazuh** — the Wazuh compose file is your Docker lesson. Don't study Docker in the abstract first.

**Step 3 — Stand up Wazuh (official docker-compose).**
This is where "learn Docker" and "start the project" merge. Generate a few events (failed SSH logins), *see them appear*. First real "it works" moment.
- **Why Wazuh first specifically:** its output shape (the archive JSON) defines every downstream component's input. You can't sensibly build the ML or dashboard until you've seen a real event. So even in test-each-part mode, Wazuh is *the* foundational part.
- Set `logall_json: yes` early so archives.json exists.
- **Expect cert errors on first boot — they always happen.** First one → paste in the log, "thought this would work because…". You've officially begun (not planning to begin — begun).

**Step 4 — ML, completely standalone (Claim B).**
Independent of the pipeline — do it in parallel if you want. Take login data (or the archive JSON Wazuh produced), feed an Isolation Forest / autoencoder in plain Python on CPU, see if it flags anomalies. No seams, runs on your hardware, no GPU. This proves the substance of your AI claim.

**Step 5 — Dashboard, standalone.**
Small page reading sample alerts from a small OpenSearch. Visible, no GPU, morale win. Show alerts tagged by source (rule vs AI).

**Step 6 — Kafka + the stub consumer.**
Least visually rewarding (pure plumbing) → fine to leave for the wiring phase. Stub = Python consumer that reads Kafka and prints/POSTs a fake alert. Proves the fork/flow with zero ML.

**Step 7 — Wire it together + writeback.**
Now connect the seams you've been assuming work: Filebeat→Kafka, Kafka→consumer, consumer→OpenSearch writeback. Handoff tests use 2 components at a time (fits 16GB).

**Step 8 — SAD diagrams alongside/after.**
Context diagram whenever. **State diagram after Step 3** (real alerts = accurate lifecycle). These document what you built → building-informs-diagrams is the right order. Not first — you've already clarified scope by talking it through.

**Step 9 — Migrate to the SIAM AI VM + deploy the hardware-bound work.** *(Now committed, not optional. This is the deadline-critical path — the VM expires 30 Nov.)*
Order matters because only this work depends on hardware that goes away:
- **9a — Get on and verify (week 1).** VPN up, SSH in, `nvidia-smi` (H100 visible, 80GB), `ls /dev/rshim*` + `lspci | grep -i blue` (DPU present, what mode), confirm Docker + NVIDIA Container Toolkit, test egress. Change the Wazuh password before bringing the stack up (shared box). Raise anything wrong in week 1 while they're still in handover mode.
- **9b — Migrate the core stack** and get it running end-to-end exactly as it does locally, on real hardware. Boring, load-bearing.
- **9c — Morpheus on the H100.** Real run, real throughput numbers. The design already matches DFP's Kafka-native shape (Part 6), so this is deployment, not redesign.
- **9d — Local LLM alert explanation** served on the H100 (vLLM + a 20–70B model), on-demand.

**Step 10 — Phase 2: the DPU network lane (committed).**
Second sensor, second coherent data slice — network flows alongside the auth lane. This is the cross-layer "X" in XDR and the part the sponsor most wants to see (DPU acceleration is named in their use-list).
- Suricata on the BlueField's Arm side, watching container-to-container traffic, emitting EVE JSON.
- EVE JSON → the same Kafka; a **separate** consumer + **separate** model (network features never mixed with auth features — see the coherent-slice rule).
- Detections tagged distinctly, surfaced on the same dashboard next to the auth lane.
- **Gate (not a cancel, a sequence):** land 9a–9d — the scoped auth-lane system, complete and defensible — *before* starting Step 10. If the core is solid with runway left, Phase 2 is the standout chapter. If time runs short, it degrades gracefully to a documented, part-built future-work item with real justification. Either way the degree-critical work is done first.

**Step 11 — Benchmarks, writeup, handover.**
Throughput/latency/GPU-utilization numbers, the rule-only vs rule+AI comparison, and the two deliverables: the academic report (grades *you* — failures included) and the sponsor handover (repo + knowledge presentation; leads with what their hardware achieved). Consent form clause 5 requires the handover — pin the date with your advisor/SIAM contact early, it's likely late Nov.

### Throughout: the failure log
Log every setup, every error, every dead end — *as it happens, ugly and real-time.* Paste actual error text + "thought X would work because…" + your guess at why it broke. This converts failure into content: it feeds บทที่ 5 (lessons learned), and it means **you can't fail to pass** — a rigorous account of real attempts, including where reality pushed back, is itself the deliverable. You already do this in pentest reports; same move, new domain.

---

## PART 5 — How to actually test the AI model (with your hardware limit)

This is the part that was thin before. The **correct** ML approach — test small, coherent datasets one at a time, offline — happens to be independent of hardware, so it held true on the old 16GB/AMD local box and still holds on the H100 VM. It was never really a compromise forced by hardware; it's just right. (Having the H100 now means the *live* pipeline and Morpheus can run for real — but the offline model-proof below stays a separate, CPU-fine, self-contained experiment. Don't conflate the two.) Here's the whole thing.

### The core idea: the model test is SEPARATE and OFFLINE
Testing the model is **not** part of the live pipeline. You don't need Kafka running, you don't need Wazuh running, you don't need anything else up. It's just: *a dataset file + a Python script + your CPU.* This is why it's small and manageable — it's isolated from all the infrastructure. You're proving one thing: "given normal data, the model learns normal; given weird data, it flags it."

### Where to get data (they said mock or from anywhere — here are the real options)
1. **Public labeled datasets (easiest, most credible):**
   - **CICIDS2017 / CIC-IDS** — network flow data, already CSV of features, labeled (normal vs attack types). Runs on CPU. The single most common choice for exactly this.
   - **UNSW-NB15** — similar, network intrusion, labeled, CSV.
   - **NSL-KDD** — older, smaller, classic, *very* light on resources — good for a first tiny test because it's small.
   - These are CSVs of pre-extracted features → **no packet processing, no GPU, no Morpheus needed.** Just load and run.
2. **Wazuh's own output** — the `archives.json` your Wazuh produces. Generate some normal activity + some attack activity (failed logins, a port scan) on your test box, collect the events, use those. Most "authentic" to your actual pipeline, but you have to generate/label it yourself.
3. **Synthetic/mock** — generate fake login records in Python (normal ones clustered around business hours + a few 3am-from-weird-IP ones). Fastest to start, least credible, but fine for proving the *mechanism* works before you get real data.
4. **Attack simulation tools** (if you want to generate realistic attack data yourself): Atomic Red Team, MITRE Caldera — these *perform* attacks so Wazuh logs them. More advanced; optional.

### The "separate test per small dataset" approach — this is exactly right
Your instinct to test each small dataset separately isn't just a hardware workaround — **it's correct ML practice AND it matches the "coherent data slice" rule.** Do it like this:

**Per experiment (one dataset, one data type):**
1. Load one small dataset (or a *subset* of a big one — you don't need all of CICIDS, take 10-50k rows).
2. Split: "normal" data to learn from + a mix of normal/anomalous to test on.
3. Train the model on normal (Isolation Forest or autoencoder — both CPU-fine on small data).
4. Test: does it flag the anomalies and leave normal alone?
5. Record the numbers (how many caught, how many false alarms).
6. **Done. Shut it down. Next dataset if you want another experiment.**

Each run is small, self-contained, uses your full RAM alone, needs no GPU, and finishes in minutes. You can do login-anomaly on auth data as one experiment, network-anomaly on CICIDS as another — *separate models, separate runs, separate writeups.* That's clean, not a compromise.

### Keeping the offline model-test light (still good practice, even with the H100)
- **Subsample big datasets** — CICIDS is huge; load 10-50k rows, not millions. Anomaly detection demonstrates fine on a subset.
- **Isolation Forest first** — it's lighter and simpler than an autoencoder, pure scikit-learn, trains in seconds. Prove the concept with it before bothering with the autoencoder.
- **Autoencoder on CPU** — PyTorch CPU mode is fine for small data. Skip GPU entirely; don't fight ROCm on the 5700 XT.
- **One dataset in memory at a time** — load, run, clear, load next. Never hold multiple big datasets at once.
- **pandas + scikit-learn + a notebook** — that's the whole toolkit. No heavy infra.

### What "the model works" looks like (your Claim B evidence)
You're aiming to be able to say, with numbers: *"On [dataset], the anomaly model flagged X% of attacks the rules would miss, with Y% false positives."* Plus the **comparison**: rules-only caught A, rules+AI caught A+B. That delta (B) is the entire value of your AI, demonstrated. That's what goes in บทที่ 4.

### How this connects back to the live pipeline
The offline-tested model is the *same logic* that (later, optionally) goes into the live Kafka consumer. You prove it works offline on a dataset → then the live consumer runs that same model on the archive stream. If you never get the live version fully wired, **the offline proof still stands on its own** as Claim B. The two are decoupled — that's the safety net.

---

## PART 6 — Verified research findings (July 2026)

*Searched current sources on Morpheus/DFP status and the modern EDR/XDR landscape. These strengthen your Chapter 2 motivation and confirm/correct technical assumptions.*

### Morpheus DFP — verified against NVIDIA docs (Morpheus 25.06)

- **DFP is real, current, and actively documented.** It's NVIDIA's flagship Morpheus workflow.
- **CONFIRMED: DFP has BOTH a training pipeline and an inference pipeline** — they communicate via a shared MLflow model store. This settles the doc's "pretrained, no training" contradiction definitively: DFP *trains per-user models on your data* (that's the entire mechanism). There is no training-free DFP. Fix the doc wording to "use Morpheus's DFP architecture, fit baselines on our data."
- **Concrete detail for your doc:** DFP requires a **minimum of 300 log records per user** to train that user's model; users below that fall back to a shared "generic user" model. Great specific to cite — it also tells you how much mock data to generate per user.
- **HUGE validation of your architecture: the official DFP streaming pipeline reads from Kafka natively** (`ControlMessageKafkaSourceStage`). Your Wazuh → Kafka → Morpheus design is literally the shape NVIDIA's own reference pipeline expects. You're not improvising the integration — you're matching the intended pattern.
- The reference DFP example ingests **Azure AD / Duo authentication logs** — i.e., auth/login data, matching your data-slice choice.
- NVIDIA's own docs: "Any data source can be fed into DFP after some preprocessing to get a feature vector per log/data point" — official support for the "general method, coherent feature vector per experiment" framing.
- Reality check from NVIDIA's own forums: people report the DFP production example is **hard to get running** with sparse documentation. Strategy holds: prove the ML concept in plain Python on CPU first (done — see failure log), *then* deploy on the provided H100. Budget real time for the Morpheus setup fight — the docs are sparse, so treat 9c as a multi-day task, not an afternoon.

### Modern EDR/XDR landscape — pros/cons with current (2025–2026) numbers for Chapter 2

Pain points (your project's motivation — now with citable stats):
- **83% of security analysts** reported feeling overwhelmed by alert volume and false positives (2025 survey).
- Average alert investigation takes **~70 minutes** (Prophet Security, 2025); **75% of MSPs** hit alert fatigue at least monthly.
- EDR out-of-the-box rules overwhelm untuned teams → analysts start bulk-closing alerts → real threats get missed. Tuning is continuous engineering, not one-time setup.
- **Nuance to include (makes your doc smarter): XDR does NOT inherently reduce false positives.** Cross-layer correlation gives richer context but can *increase* total alert volume. So "XDR alone" isn't the fix — which is precisely the gap your AI layer addresses.

What the industry is doing about it (validates your design):
- **Leading SOCs in 2026 use LLMs for Level-1 alert triage** — ingesting alerts, correlating context, auto-resolving false positives before a human sees them. Gartner (2025): AI-assisted triage cuts per-alert investigation from 15–20 min to **2–3 min**. → Your LLM-explains-alerts component isn't a gimmick; it's literally the current industry direction. Cite this.
- High-performing orgs target MTTR of 10 min–1 hr — context for your MTTR ≤ 30s auto-response target (yours is auto-response time, theirs includes human loop; distinguish the two in your doc so the comparison is honest).
- EDR = deep endpoint specialist; XDR = broad correlator across endpoint/network/cloud/email/identity. Open XDR (your Wazuh approach) = vendor-neutral, integrates third-party tools, trades some correlation sophistication for flexibility. Wazuh is the leading open-source example.

### What this changes in your doc
1. §2.1.5 / motivation: swap in the 2025–2026 stats above (stronger than the older ones).
2. Add the "XDR doesn't inherently fix false positives" nuance — it sharpens your gap statement.
3. Fix the pretrained/training wording per the DFP confirmation.
4. Add "DFP consumes Kafka natively" to your architecture justification — it turns a design choice into a documented best practice.
5. Frame the LLM component as aligned with the 2026 AI-SOC-triage trend, with the Gartner numbers.

---

## The mental anchors (when you feel lost again)

1. **Scope = one sentence** (general anomaly detection, demonstrated on one coherent dataset, rest = future work). Every "do I need X?" → does it serve the sentence?
2. **It's all JSON** once it leaves Wazuh — the plumbing is content-agnostic, don't overthink data types for the pipes.
3. **Generality is in the METHOD, not the data-juggling** — one model on one coherent data slice per experiment. Don't mix logins + network + files into one model (feature soup = broken). Many *related* features = fine; many *unrelated* types mashed together = the real "too many features" problem.
4. **archives.json, NOT alerts.json** for the AI. The one technical thing that must be right.
5. **Morpheus is just a fast wrapper over ML** — prove the ML on CPU first; then (Sep 2026) *deploy* it on the provided H100. It's now a real deployed component, not only a documented target — but the CPU proof still stands alone as Claim B if the deployment runs short.
6. **70% is easy assembly, 30% is iterative craft** — don't dread the plumbing as if it's hard; only the model-tuning is slow, and it's small + isolated.
7. **"Good" = works + understood + honestly explained** — reachable, rewards your honesty instinct, not asymptotic perfection.
8. **The next step is a terminal, not more planning** — you're past the point where more understanding helps. Download the Ubuntu ISO.
