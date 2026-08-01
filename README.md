# AI-Enhanced XDR

Wazuh + Kafka + anomaly detection pipeline that catches attacks signature-based rules miss.

Built for **CS497 Computer Science Project I**, sponsored by SIAM AI Cloud. Endpoint events flow through Wazuh, stream through Apache Kafka, and are analysed by an unsupervised anomaly-detection model (Isolation Forest) that flags behavioural deviations — including slow, paced attacks that rule-based correlation does not catch. Detections are written back to OpenSearch, tagged separately from rule alerts, and shown side by side on a custom dashboard.

NVIDIA Morpheus is the documented GPU deployment target; this implementation runs on CPU as a proof of concept (see `docs/` for the full architecture writeup and the reasoning behind that decision).

## Architecture

```
Endpoint → Wazuh Agent → Wazuh Manager → archives.json
                                              │
                                    archive_producer.py (tail -F)
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
dashboard/      FastAPI backend + detection-split dashboard (HTML/JS)
scripts/        traffic generation, orchestration, ML experiments
docs/           architecture notes, results log, failure log
```

## Setup

Requires Docker, Docker Compose, and Python 3.10+.

**1. Wazuh stack**
```bash
cd wazuh
docker compose -f generate-indexer-certs.yml run --rm generator
sudo sysctl -w vm.max_map_count=262144
docker compose up -d
```
Dashboard: `https://localhost` (admin / SecretPassword — change before any real use)

**2. Deploy a Wazuh agent** on the endpoint you want to monitor, pointed at the manager. Enable `logall_json: yes` in `wazuh/config/wazuh_cluster/wazuh_manager.conf` (already set in this repo) so the archive captures every event, not just rule matches.

**3. Kafka**
```bash
cd ../ai-stack
docker compose -f ai-stack.yml up -d
```

**4. Python environment**
```bash
python3 -m venv venv
source venv/bin/activate
pip install -r requirements.txt
```

**5. Run the pipeline**
```bash
cd ../ai-stack/pipeline
python archive_producer.py &      # Wazuh archive -> Kafka
python detection_consumer.py &    # Kafka -> Isolation Forest -> OpenSearch

cd ../../dashboard
uvicorn main:app --host 0.0.0.0 --port 8000 &
python3 -m http.server 8080 &
```
Dashboard: `http://localhost:8080/dashboard.html`

## Why this architecture

- **`logall_json` enabled**: Wazuh's default alert log only contains events that matched a rule. The anomaly model needs the full event stream — including everything rules *don't* flag — or it can never detect what signature-based detection misses.
- **Kafka between Wazuh and the model**: decouples the fast path (rules → dashboard, always works) from the AI path (archive → model), so a slow or failed model run never affects standard alerting.
- **Isolation Forest over a rolling window buffer**: unsupervised, so it requires no labelled attack data — it learns what "normal" looks like for this environment and flags deviations. Windowed aggregation (not per-event scoring) lets it catch slow, low-and-slow attacks that evade fixed-threshold correlation rules.
- **Separate `ai-detections-*` index + custom rule ID range (100000+)**: keeps AI-generated findings distinguishable from native Wazuh rule alerts at query and display time.

Full reasoning, evaluation methodology, and results are in `docs/`.

## Status

In development. Core detection pipeline (ingestion → streaming → anomaly detection → writeback → dashboard) is working and validated against controlled attack scenarios with independent ground truth. Automated response (block/isolate), local LLM alert explanation, and GPU deployment on Morpheus are in progress.
