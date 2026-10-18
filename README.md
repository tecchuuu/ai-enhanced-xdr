# AI-Enhanced XDR

Wazuh + Kafka + anomaly detection pipeline that catches attacks signature-based rules miss.

Built for **CS497 Computer Science Project I**, sponsored by SIAM AI Cloud. Endpoint events flow through Wazuh, stream through Apache Kafka, and are analysed by an unsupervised anomaly-detection model (Isolation Forest) that flags behavioural deviations — including slow, paced attacks that rule-based correlation does not catch. Detections are written back to OpenSearch, tagged separately from rule alerts, and shown side by side on a custom dashboard.

The CPU implementation (Isolation Forest) is the proof of method; NVIDIA Morpheus on GPU is the deployment target. SIAM AI Cloud has provisioned an H100 80GB VM (Sep–Nov 2026), on which Morpheus's DFP model and a local LLM explainer now run (see `docs/` and `SETUP.md`). A network-detection lane on the VM's BlueField-3 DPU is out of scope.

## Architecture

```
Endpoint → Wazuh Agent → Wazuh Manager → archives.json
                                              │
                                    Filebeat (Kafka output)
                                              │
                                         Apache Kafka
                                              │
                                    detection_consumer.py
                                    (windowing → Isolation Forest)
                                              │
                                          OpenSearch
                                    (ai-detections-* index)
                                              │
                                    FastAPI + dashboard
                                    (rule alerts vs AI detections)
```

## Repo structure

```
wazuh/          Wazuh manager/indexer/dashboard — Docker Compose + config
ai-stack/       Kafka (KRaft mode) + streaming pipeline scripts
dashboard/      FastAPI backend + SOC console (React + EUI)
scripts/        traffic generation, orchestration, ML experiments
docs/           architecture notes, results log, failure log
```

## Setup

Requires Docker and Docker Compose. Everything runs as containers; Python and
Node on the host are only for the optional steps at the end.

**1. Wazuh stack**
```bash
cd wazuh
docker compose -f generate-indexer-certs.yml run --rm generator
sudo sysctl -w vm.max_map_count=262144
docker compose -p luckyfive_wazuh up -d
```
Dashboard: `https://localhost` (admin / SecretPassword — change before any real use)

**2. Deploy a Wazuh agent** on the endpoint you want to monitor, pointed at the manager. Enable `logall_json: yes` in `wazuh/config/wazuh_cluster/wazuh_manager.conf` (already set in this repo) so the archive captures every event, not just rule matches.

**3. Credentials**
```bash
cp dashboard/.env.example dashboard/.env
# fill in the Wazuh API + OpenSearch credentials
```

**4. Everything after Wazuh**
```bash
cd ../ai-stack
docker compose -p luckyfive_kafka -f ai-stack.yml up -d --build
```
Five services from `ai-stack/ai-stack.yml`: Kafka, **Filebeat** (manager
archive → Kafka), the **auth** and **web detectors**, and the **API**, which
also serves the console: `http://<host>:8000`. The first run builds the image
(`Dockerfile`: console + Python, a few minutes). After pulling new code, run the
same command — `--build` rebuilds only what changed. After editing
`dashboard/.env`, `restart` instead. Logs: `docker compose -p luckyfive_kafka
-f ai-stack.yml logs -f auth-detector` (or `api`, `filebeat`, …).

Filebeat reads the manager's log volume, `luckyfive_wazuh_wazuh_logs` — after a
different `-p` in step 1, set `WAZUH_LOGS_VOLUME` in `ai-stack/.env`.

**Optional — console development** (Node 20.19+): `cd dashboard/frontend &&
npm install && npm run dev` serves it on `:5173` with live reload and proxies
`/api` to `:8000` (`API_TARGET=http://host:port npm run dev` if the API is
elsewhere).

**Optional — offline scripts** (`scripts/`: model comparison, explainer test):
```bash
python3 -m venv ml-venv && ml-venv/bin/pip install -r requirements.txt
```

The console is a Wazuh-style UI (same EUI component library)
with rule + AI alerts, a shared time range and agent filter, server-side search
(IP, user, rule ID, text), time charts, threat categories, alert detail flyout
with related events and the raw document, a **Why it fired** panel on AI
detections (the window's features against the model's own baseline and score
cutoff), an IP pivot (every alert from an address, targeted accounts, block
state — click any IP),
per-alert triage (status / assignee / note / mark-false-positive), a
**Detection split** timeline (rule alerts and AI detections minute by minute,
the AI-only minutes flagged), a **Metrics** page (live rule-vs-AI comparison,
false-positive rate, MTTR, detections per model), one-click IP
blocking via Wazuh Active Response with an unblock action and current-block
view, audit-logged response history, live agent status, and a **Pipeline** page
(OpenSearch, Wazuh API, each detector's heartbeat, explainer) so a quiet console
can be told apart from a stopped detector. Light and dark modes are
both selectable (header toggle, persisted); each has its own validated color
steps in `src/theme/palette.js` rather than one being a flip of the other. Console
internals and contracts: `docs/dashboard-build-notes.md`.

## Why this architecture

- **`logall_json` enabled**: Wazuh's default alert log only contains events that matched a rule. The anomaly model needs the full event stream — including everything rules *don't* flag — or it can never detect what signature-based detection misses.
- **Kafka between Wazuh and the model**: decouples the fast path (rules → dashboard, always works) from the AI path (archive → model), so a slow or failed model run never affects standard alerting.
- **Isolation Forest over a rolling window buffer**: unsupervised, so it requires no labelled attack data — it learns what "normal" looks like for this environment and flags deviations. Windowed aggregation (not per-event scoring) lets it catch slow, low-and-slow attacks that evade fixed-threshold correlation rules.
- **Separate `ai-detections-*` index + custom rule ID range (100000+)**: keeps AI-generated findings distinguishable from native Wazuh rule alerts at query and display time.

Full reasoning is in `docs/`: `project_plan.md` (original architecture plan),
`failure_log.md` (every error, dead end, and decision with rationale),
`results_log.md` (claims, metrics, and evidence), `ROADMAP.md` (what's next and
how the deferred pieces attach), `dashboard-build-notes.md` (console additions
and their contracts). Deploying on the SIAM VM: `SETUP.md`.

**Test traffic:** attack scenarios were generated with local scripts (not
committed) — any SSH brute-force source works to reproduce, e.g. repeated
`ssh invalid-user@<vm-ip>` or `hydra` from another host on the VM's network.
Attack from a *different* machine so the source IP is real and blockable.

## Status

Core detection pipeline (ingestion → streaming → anomaly detection → writeback → dashboard) is working and validated against controlled attack scenarios with independent ground truth. Detections are enriched with heuristic threat categories (MITRE ATT&CK-mapped) and per-window source IPs, severity scales with anomaly score, and manual response (IP block via Wazuh Active Response, with audit log) works end to end from the console.

On the SIAM VM (H100 80GB, Sep–Nov 2026), which lifted the earlier CPU-only/AMD/low-RAM constraints: the inference slot is a registry — Isolation Forest, a PyTorch autoencoder and Morpheus's DFP autoencoder swap by one env var (`docs/results_log.md` R12, R14, R16) — and the LLM explainer (`dashboard/explainer.py`) runs live on a local model via Ollama (R15). The anomaly model itself is swappable — Isolation Forest is the current occupant of the inference stage, not a design commitment. A network-detection lane on the VM's BlueField-3 DPU is out of scope (decided 2026-10-17).

## Limitations

- **Detection plane is co-located with the monitored host** for the proof of concept. Detection itself is unaffected, but log tamper-resistance is not: a root-level compromise of the VM can destroy local evidence before it is acted on. A production deployment isolates the Wazuh manager / Kafka / OpenSearch onto a separate host; the pipeline design (Kafka between capture and model) is what makes that split a configuration change rather than a rewrite.
- **Response is manual by default.** Anomaly detection carries false positives, so AI detections are routed to a human rather than auto-blocked. Automatic response (Wazuh Active Response `firewall-drop`) is appropriate only for the highest-confidence tier. Unblocking is best-effort — Wazuh exposes no first-class API undo (see `docs/dashboard-build-notes.md`).
- **Host-side detection only.** Two anomaly lanes run on endpoint logs: authentication (evaluated, R10) and web access logs (`ai-stack/pipeline/web_detection_consumer.py`, rule 100002, validated R11). A host/FIM detector is designed (`docs/ROADMAP.md`) but not built, and a network lane is out of scope — so cross-layer coverage is endpoint logs only, with no network-flow view.
