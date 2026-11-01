# AI-Enhanced XDR

Wazuh + Kafka + behavioural anomaly detection, to catch the attacks signature-based rules miss.

Built for **CS497–CS498 Computer Science Project I–II**, sponsored by SIAM AI Cloud. Wazuh collects
and correlates endpoint events as usual; its full event archive also streams through Apache Kafka to
unsupervised detectors that score one-minute windows of SSH and web activity. Their detections are
written to their own OpenSearch index and shown beside Wazuh's rule alerts in a SOC console, with an
explanation from a local LLM and human-confirmed response through Wazuh Active Response.

On the sponsor's H100 VM the detector slot holds three interchangeable models — Isolation Forest, a
PyTorch autoencoder and **NVIDIA Morpheus's DFP model** — and the SSH lane also runs on the **Morpheus
pipeline runtime**. In the evaluation, rules and models caught different attacks: Wazuh's operational
ruleset (level 10+) missed a distributed brute force entirely while every model caught it, and only
Morpheus DFP caught low-and-slow password guessing (results below).

## Architecture

```
 monitored host ─ /var/log (read-only) ─┐
 other endpoints ─ Wazuh agents ────────┤
                                        ▼
                               Wazuh manager ──► rule alerts (wazuh-alerts-*)
                                        │ archive: every event (logall_json)
                                     Filebeat
                                        │
                              Apache Kafka (wazuh-archives)
                  ┌─────────────────────┼─────────────────────┐
            auth-detector          web-detector          morpheus-auth
            (SSH, CPU model)       (web, CPU model)      (SSH, Morpheus DFP on the GPU)
                  └─────────────────────┼─────────────────────┘
                                        ▼
                         OpenSearch (ai-detections-*, heartbeats)
                                        │
                     FastAPI + SOC console (:8000) ◄── Ollama (LLM explainer)
                                        │
                       Wazuh API ──► Active Response (firewall-drop on the agent)
```

## Repo structure

```
wazuh/          Wazuh manager / indexer / dashboard + the project's own agent — Docker Compose + config
ai-stack/       Kafka, Filebeat, the detectors (pipeline/) and the Morpheus pipeline (morpheus/)
dashboard/      FastAPI backend, LLM explainer, SOC console (React + EUI)
lab/            lab dataset: synthetic normal traffic + scripted attacks with ground truth
scripts/        demo run, evaluation (AIT-LDS, lab), Wazuh rule replay, explainer test
docs/           results log, failure log, roadmap, build notes, security, dataset selection
```

## Setup

**Requirements:** Docker with Compose. For the GPU parts: an NVIDIA GPU with the NVIDIA Container
Toolkit and a Morpheus conda environment (the `morpheus-auth` service), and Ollama (the LLM
explainer). Without them everything else still runs. `SETUP.md` is the full walkthrough for the SIAM
VM, including a shared machine where another Wazuh already holds the default ports.

Every command below starts from the repository root.

**1. Wazuh stack**
```bash
cp wazuh/.env.example wazuh/.env   # host ports; the defaults suit a machine you own
cd wazuh
docker compose -f generate-indexer-certs.yml run --rm generator
sudo sysctl -w vm.max_map_count=262144
docker compose -p luckyfive_wazuh up -d
cd ..
```
The first `up` also builds the project's own agent container (`luckyfive-agent`), which carries out
blocks through Active Response. Dashboard: `https://localhost` — user `admin`, password
`SecretPassword`. Change it before any real use, the way `SETUP.md` §3 describes (inside the
indexer first), and only then set `INDEXER_PASSWORD` in `wazuh/.env` and `OS_PASS` in
`dashboard/.env` to match: a password that differs anywhere quietly breaks logins and alert
shipping (failure log Entry 26).

**2. What Wazuh reads**

- **SSH, on this host:** the manager mounts the host's `/var/log` read-only and reads
  `/var/log/host/auth.log` (`wazuh/config/wazuh_cluster/wazuh_manager.conf`). The directory is
  mounted, not the file, because the weekly log rotation replaces the file (failure log Entry 44).
  The host needs sshd logging to `/var/log/auth.log` (rsyslog).
- **Web:** mount the web server's log directory the same way and add a `<localfile>` with
  `log_format apache`.
- **Other machines:** install a Wazuh agent pointed at this manager.
- `logall_json: yes` (already set) makes the archive keep every event, not only rule matches.

**3. Configuration** (secrets; not in git)
```bash
cp dashboard/.env.example dashboard/.env
cp ai-stack/.env.example ai-stack/.env
```
- `dashboard/.env`: the Wazuh API and OpenSearch credentials; `KAFKA_BOOTSTRAP`, which must match
  `KAFKA_HOST_PORT` in `ai-stack/.env`; the explainer (`EXPLAINER_PROVIDER=ollama`,
  `OLLAMA_MODEL=gemma3:12b`).
- **On any machine others can reach,** also set `DASHBOARD_API_KEY` (e.g. `openssl rand -hex 24`;
  the console asks for it once per browser) and `BLOCK_ALLOWLIST` (your gateway and workstation, which
  the console then refuses to block). Without a key, anyone who reaches port 8000 can read alerts and
  block addresses.
- `ai-stack/.env`: `KAFKA_HOST_PORT`; `WAZUH_LOGS_VOLUME` if step 1 used a different `-p`;
  `MORPHEUS_CONDA` if Miniforge is not at `/LuckyFive/miniforge3`.

**4. Everything after Wazuh**
```bash
cd ai-stack
docker compose -p luckyfive_kafka -f ai-stack.yml up -d --build
```
Six services from `ai-stack/ai-stack.yml`: Kafka, **Filebeat** (manager archive → Kafka), the
**auth** and **web detectors**, the SSH lane again as an **NVIDIA Morpheus pipeline** on the GPU
(`morpheus-auth`, `SETUP.md` §7–7b), and the **API**, which also serves the console at
`http://<host>:8000`. Without an NVIDIA GPU and the Morpheus environment, start the other five:
```bash
docker compose -p luckyfive_kafka -f ai-stack.yml up -d --build kafka filebeat auth-detector web-detector api
```
The first run builds the image (`Dockerfile`: console + Python, a few minutes). After pulling new
code, run the same command — `--build` rebuilds only what changed. After editing `dashboard/.env`,
`restart` the services instead. Logs: `docker compose -p luckyfive_kafka -f ai-stack.yml logs -f
auth-detector` (or `api`, `filebeat`, …).

**5. LLM explainer (optional):** Ollama on the host with `gemma3:12b` and its context capped at 4,096
tokens (`SETUP.md` §6). Without it the console works; only the Assistant tab is unavailable.

**6. Try it**
```bash
bash scripts/demo_run.sh
```
Brings up both stacks and runs a scripted 15-minute SSH attack in the background (brute force at
minute 6, password spray at minute 9); detections appear after about ten minutes, once each detector
has ten one-minute windows. An attack from the host itself comes from `::1`, which the console
refuses to block. To show a real block, attack from another machine, or from a container on its own
Docker network (e.g. `10.99.0.0/24`), so the block cannot affect anything else.

**Optional — console development** (Node 20.19+): `cd dashboard/frontend && npm install && npm run
dev` serves it on `:5173` with live reload and proxies `/api` to `:8000` (`API_TARGET=http://host:port
npm run dev` if the API is elsewhere).

**Optional — offline evaluation** (`scripts/`, `lab/`): `python3 -m venv ml-venv && ml-venv/bin/pip
install -r requirements.txt`. The datasets and protocol are in `docs/dataset_selection.md`, the lab
traffic and attacks in `lab/README.md`; the GPU models run from the Morpheus environment.

## The console

A Wazuh-style UI (same EUI component library) with an **Alert queue** (open alerts from both sources,
most severe and longest-waiting first, its open critical/high count in the menu), **Wazuh alerts** and
**AI detections** pages laid out alike (a chart, filters, the table) that page through every alert on
the server, a shared time range and agent filter, server-side search (IP, user, rule ID, text),
Wazuh's own severity bands in the usual SOC colours (critical red, high orange, medium yellow, low
slate), alert detail flyout with related events and the raw document, a **Why it fired** panel on AI
detections (the minute's numbers against what the model saw as typical, and its score cutoff), an
**Assistant** tab (the local LLM explains a detection and answers follow-up questions; the verdict is
computed in code), an IP pivot (every alert from an address, targeted accounts, block state — click
any IP), per-alert triage (status / assignee / note / mark-false-positive), a **Rules vs AI** page
(rule alerts and AI detections minute by minute, with the counts, "flagged only by AI", and the
false-positive rate among reviewed detections), one-click IP blocking via Wazuh Active Response with
guardrails (loopback, the agent's and manager's addresses, an allowlist) and a manual-unblock action,
an audit-logged response history, live agent status, a detector status indicator in the header, and a
**Pipeline** page (OpenSearch, Wazuh API, each detector's check-in, the AI assistant) so a quiet
console can be told apart from a stopped detector. Light and dark modes are both selectable (header
toggle, persisted); each has its own color steps in `src/theme/palette.js` rather than one being a
flip of the other. Console internals and contracts: `docs/dashboard-build-notes.md`.

## Why this architecture

- **`logall_json` enabled**: Wazuh's default alert log only contains events that matched a rule. The anomaly models need the full event stream — including everything rules *don't* flag — or they can never detect what signature-based detection misses.
- **Kafka between Wazuh and the models**: decouples the fast path (rules → dashboard, always works) from the AI path (archive → model), so a slow or failed model never affects standard alerting, and each detector reads every event on its own consumer group.
- **Unsupervised models over one-minute windows**: no labelled attack data needed — they learn what "normal" looks like for this environment and flag deviations. Aggregating a minute (not scoring single events) is what exposes attacks spread across many addresses or slowed below per-source thresholds.
- **A model slot, not a model**: Isolation Forest, the autoencoder and Morpheus DFP share one feature definition (`ai-stack/pipeline/features.py`, used live and in the evaluation) and swap by one setting.
- **Separate `ai-detections-*` index + custom rule ID range (100000+)**: keeps AI-generated findings distinguishable from native Wazuh rule alerts at query and display time.
- **The LLM reads, never acts**: it explains detections from computed facts; blocking is always a human decision.

Full reasoning is in `docs/`: `project_plan.md` (original architecture plan),
`failure_log.md` (every error, dead end, and decision with rationale),
`results_log.md` (claims, metrics, and evidence), `ROADMAP.md` (what's next and
how the deferred pieces attach), `dashboard-build-notes.md` (console additions
and their contracts), `security.md` (what the console protects against, known
gaps, production tiering), `dataset_selection.md` (which datasets the evaluation uses,
why, and the evaluation protocol). Deploying on the SIAM VM: `SETUP.md`.

## Status and results

Deployed on the SIAM VM (H100 80GB, Sep–Nov 2026): the Wazuh stack, the streaming pipeline, both CPU
detectors, the Morpheus pipeline and the console run as containers started by one command; the LLM
explainer runs on Ollama (gemma3:12b). Evaluated train-once against independent ground truth
(`docs/results_log.md`):

- **Lab SSH lane (R18):** Morpheus DFP PR-AUC 0.97, recall 0.94, 0.3 false alarms/day; Isolation Forest 0.92 / 0.42.
- **Distributed brute force (10 addresses):** Wazuh at level 10+ recall 0.00 — every model 1.00.
- **Low-and-slow guessing (one attempt per 1–6 min):** Morpheus DFP 0.83–1.00; every other model ≤0.40, Wazuh at level 10+ ≤0.17.
- **Web lane:** the autoencoder and DFP lead on the lab data (PR-AUC 0.88 / 0.89), and DFP has the best or tied-best PR-AUC in every public AIT-LDS scenario (R17). Single low-volume requests (webshell commands, one injection) barely change a minute's counts; Wazuh's signatures cover those.
- **Live:** the SSH lane on the Morpheus runtime caught a scripted demo attack's brute force and spray (R19); a console block of a test attacker dropped its traffic (2026-11-01).

## Limitations

- **Detection plane is co-located with the monitored host** for the proof of concept. Detection itself is unaffected, but log tamper-resistance is not: a root-level compromise of the VM can destroy local evidence before it is acted on. A production deployment isolates the Wazuh manager / Kafka / OpenSearch onto a separate host; the pipeline design (Kafka between capture and model) is what makes that split a configuration change rather than a rewrite.
- **Response is manual by default.** Anomaly detection carries false positives, so AI detections are routed to a human rather than auto-blocked. Automatic response (Wazuh Active Response `firewall-drop`) is appropriate only for the highest-confidence tier. Unblocking is manual — Wazuh's API cannot undo a firewall-drop, so the console records the unblock, gives the command to remove the rule on the agent, and keeps the IP listed until the removal is confirmed (failure log Entry 45).
- **Host logs only.** The SSH and web lanes read endpoint logs; a host/FIM detector is designed (`docs/ROADMAP.md`) but not built, and a network lane on the VM's BlueField-3 DPU is out of scope (decided 2026-10-17).
- **Synthetic normal traffic.** The lab's and AIT's normal users are scripted, so measured false-alarm rates are likely optimistic; the pattern across methods is more reliable than any single figure.
- **The live detectors flag a fixed share.** They refit every minute and flag about 15% of buffered windows, so they always flag something; detection quality is measured in the train-once evaluation, not live.
- **Times are UTC.** The `hour` feature and the "off-hours" category use UTC hours (06:00–22:00 counts as working time), matching the evaluation data; in Thailand that labels mornings before 13:00 as off-hours.
- **Console security is lab-level**: one shared access key, plain HTTP, self-declared analyst names (`docs/security.md`).
