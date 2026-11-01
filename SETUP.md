# SETUP — running on the SIAM AI VM

Overall flow. Assumes you know `git clone` + `pip install -r requirements.txt`.
Only the non-obvious / SIAM-specific steps are spelled out.

## What's different on this box
- **Shared Docker daemon** (2 groups per VM) → one Docker service runs both groups' containers; your *directory does not isolate you*. Prefix compose commands with `-p luckyfive_wazuh` / `-p luckyfive_kafka` so container and volume names stay distinct. **Host ports are the real conflict** — they bind once regardless of project name, and `-p` does NOT fix that. Every host port is configurable now: see **§0** and claim free ones rather than waiting for the other group to stop.
- **Shared hardware** → keep everything in Docker; `docker compose down` when you stop (removes containers, so nothing lingers on reboot).
- **No Claude API key here** → the LLM explainer runs on **Ollama** (local model on the H100), not Anthropic.
- **Secrets (`.env`) are NOT in git** → recreate on this box (step 4).
- **Only `/` is large.** `/` is 3.3 TB; `/home`, `/var` and `/tmp` are each ~10 GB LVs. Anything multi-gigabyte must be told to use `/`: Docker (step 1), conda (step 8), and pip (`export TMPDIR=/LuckyFive/tmp PIP_CACHE_DIR=/LuckyFive/pip-cache`). Three separate outages came from this — failure log Entries 23, 29, 30.

## 0. Shared VM: claim free host ports first

Two groups share this VM and **host ports bind once** — container names, compose
project names (`-p luckyfive_*`) and separate volumes do *not* isolate them. If
the other group's stack is up, yours will not start, and (worse) a client
pointed at a default port can silently attach to *their* broker.

Check what is taken:

```
docker ps --format 'table {{.Names}}\t{{.Ports}}'      # theirs are edrxdr-* / wazuh-*
ss -tlnp | grep -E ':(443|514|1514|1515|8000|9092|9200|55000)\b'
```

Every host port is now configurable, so you never have to wait for them. Observed
2026-10-10: the other group held 9200, 9201, 9092, 1514, 1515, 55000 and 8443.
Working set that avoids those:

| File | Setting | Value |
|---|---|---|
| `wazuh/.env` | `INDEXER_PORT` | 9202 |
| `wazuh/.env` | `DASHBOARD_PORT` | 443 (free; theirs is on 8443) |
| `wazuh/.env` | `WAZUH_AGENT_PORT` / `WAZUH_ENROLL_PORT` | 1516 / 1517 |
| `wazuh/.env` | `WAZUH_SYSLOG_PORT` | 515 |
| `wazuh/.env` | `WAZUH_API_PORT` | 55001 |
| `wazuh/.env` | `INDEXER_PASSWORD` | your admin password |
| `ai-stack/.env` | `KAFKA_HOST_PORT` | 29092 |
| `ai-stack/.env` | `WAZUH_LOGS_VOLUME` | empty (= `luckyfive_wazuh_wazuh_logs`, matches `-p luckyfive_wazuh`) |
| `dashboard/.env` | `OS_PORT` | 9202 |
| `dashboard/.env` | `KAFKA_BOOTSTRAP` | localhost:29092 |
| `dashboard/.env` | `WAZUH_API_URL` | https://localhost:55001 |

Copy from the `.env.example` next to each. Compose reads `.env` from the
directory of the compose file, so run compose from `wazuh/` and `ai-stack/`.

**Two things that bite:**
- `KAFKA_HOST_PORT` and `KAFKA_BOOTSTRAP` must agree. Kafka advertises its port
  to clients, so a mismatch redirects them after connecting. The consumers print
  the broker address at startup — read that line.
- **Don't touch the VM's own Wazuh agent** (`/var/ossec`, the `wazuh-agent`
  service). It reports to the *other group's* manager on 1514, and an agent can
  only report to one manager — re-pointing it to yours silently cuts theirs off
  (found 2026-10-18: it had sat on 1514 since our 10-11 port move). Ours is a
  separate agent in a container, part of our compose stack — see §3b.

Courtesy, not a dependency: tell the other group which ports you took.

## 1. System (sudo, once)
- `sudo apt install -y git python3-venv python3-pip curl`
- Docker (official repo) + **NVIDIA Container Toolkit**; add user to `docker` group; `sudo nvidia-ctk runtime configure && sudo systemctl restart docker`
- Kernel param before Wazuh: `sudo sysctl -w vm.max_map_count=262144`
- Verify GPU in a container: `docker run --rm --gpus all nvidia/cuda:12.4.0-base-ubuntu22.04 nvidia-smi`

## 2. Project + venv
- `git clone <repo> && cd ai-enhanced-xdr`
- Optional — the pipeline and API run in containers (§5). The venv is only for the offline tools in `scripts/` (model comparison, explainer test): `python3 -m venv ml-venv && ml-venv/bin/pip install -r requirements.txt`
- Optional — the autoencoder model (`DETECTOR_MODEL=autoencoder`) needs PyTorch, kept out of `requirements.txt` so the base install stays light: `ml-venv/bin/pip install torch` (the default Linux build is CUDA-enabled → uses the H100). Isolation Forest needs no torch.

## 3. Wazuh stack
- `cd wazuh && docker compose -p luckyfive_wazuh up -d`  (`-p` optional; namespaces your containers)
- Change the admin password: `hash.sh` → put hash in `internal_users.yml` → recreate indexer → `securityadmin.sh -f ... -t internalusers`. (See failure_log for the exact sequence + the bind-mount gotcha.)

## 3b. Our agent (container)
The `wazuh.agent` service in `wazuh/docker-compose.yml` is our group's agent: it enrolls with our manager on `WAZUH_ENROLL_PORT` and reports on `WAZUH_AGENT_PORT` as `luckyfive-agent`, so the VM's host agent stays with the other group. It comes up with the rest of the stack (the first `up` builds it — needs internet for Wazuh's apt repo). It runs Active Response only — the console's **Block IP** — on host networking, so blocks land in the VM's firewall (keep `BLOCK_ALLOWLIST` set, §4: a block affects the whole shared VM). SSH events don't need it: the manager reads the host's auth log directly, through a read-only mount of the whole `/var/log` directory (`/var/log/host/auth.log` in `ossec.conf`). Mount the directory, never the single file — Ubuntu's weekly logrotate replaces `auth.log`, and a file mount stays on the old one, silently (failure log Entry 44).

**Unblocking is manual.** Wazuh's API cannot undo a firewall-drop (failure log Entry 45), so the console's Unblock records the request and shows the commands; run them inside this agent's container, repeating until none is left, then click **Confirm removed**:

    docker exec luckyfive_wazuh-wazuh.agent-1 sh -c 'while iptables -D INPUT -s <IP>/32 -j DROP 2>/dev/null; do :; done; while iptables -D FORWARD -s <IP>/32 -j DROP 2>/dev/null; do :; done'

Already-running stack, bring up just the agent:

    cd wazuh && docker compose -p luckyfive_wazuh up -d --build wazuh.agent
    docker logs -f luckyfive_wazuh-wazuh.agent-1      # want: Connected to the server ([127.0.0.1]:1516/tcp)

The console's **Agents** page then lists `luckyfive-agent` as active. The key lives in the `wazuh_agent_etc` volume, so restarts reuse it; deleting that volume re-enrolls under a new id. Optional tidy-up — remove the stale host-agent record (id 003) from *our* manager; it doesn't affect the other group's:

    docker exec luckyfive_wazuh-wazuh.manager-1 /var/ossec/bin/manage_agents -r 003

## 4. .env (secrets — not in git)
    cp dashboard/.env.example dashboard/.env
Set: `OS_HOST=localhost`, `OS_PORT=<INDEXER_PORT from §0, 9202 here>`, `OS_USER=admin`, `OS_PASS=<the pw from step 3>`,
`EXPLAINER_PROVIDER=ollama`, `OLLAMA_MODEL=gemma3:12b` (§6; no ANTHROPIC key),
`WAZUH_CONTAINER=luckyfive_wazuh-wazuh.manager-1` (only for the old `archive_producer.py`, kept as a fallback; Filebeat finds your manager by its log volume instead, §5).

**Shared box → lock the console down.** The API listens on `0.0.0.0:8000` and can push firewall blocks to agents, so anyone on the VM's network — the other group included — could call it. In the same `.env`:
- `DASHBOARD_API_KEY=<a long random string>` — the console asks for it once per browser (`openssl rand -hex 24` makes one). Empty means the API is open to anyone on the VPN; this VM ran that way until 2026-11-01. Check from any machine: `curl http://<vm>:8000/api/health` must say `"auth_required":true`.
- `BLOCK_ALLOWLIST=<VM gateway IP>,<your workstation / VPN range>` — addresses the console refuses to block, on top of its built-in rules (loopback; unspecified, multicast, link-local and reserved addresses; the agent's and the manager's own IPs; your own address). Private ranges are *not* refused — lab attackers come from them — so the VPN gateway (`172.16.30.254` here) must be listed: everything from your PC arrives through it.

After editing, restart the services that read it (they load `.env` at startup). The key and the allowlist are read only by the API; restarting the detectors also empties their window buffers, so they warm up again:

    (cd ai-stack && docker compose -p luckyfive_kafka -f ai-stack.yml restart api)
    (cd ai-stack && docker compose -p luckyfive_kafka -f ai-stack.yml restart api auth-detector web-detector)   # after changing detector settings

## 5. Kafka + pipeline + API (all containers)

    (cd ai-stack && docker compose -p luckyfive_kafka -f ai-stack.yml up -d --build)

That one command runs everything after Wazuh, from `ai-stack/ai-stack.yml`:

| Service | What it is |
|---|---|
| `kafka` | the broker |
| `filebeat` | ships every Wazuh event from the manager's archive into Kafka (`ai-stack/filebeat/filebeat.yml`) |
| `auth-detector`, `web-detector` | the two detection consumers (CPU, Isolation Forest) |
| `morpheus-auth` | the SSH lane again as a Morpheus pipeline, DFP on the GPU (§7b) |
| `api` | FastAPI + the built console on `:8000` |

- **Order:** Wazuh (§3) and `dashboard/.env` (§4) first. Filebeat reads the manager's log volume by name (`WAZUH_LOGS_VOLUME`, §0) and `up` refuses to start until it exists — deliberate: it can only ever read *our* manager's archive. The detectors and API refuse to start without `dashboard/.env`.
- **Run it from `ai-stack/`** so compose reads `ai-stack/.env`.
- **First run** builds the `luckyfive/ai-xdr` image (repo-root `Dockerfile`: the console with Node, then Python + `requirements.txt`) — a few minutes, needs internet. **After `git pull`, run the same command again**: `--build` rebuilds what changed, and only the services whose image changed are restarted. Without `--build`, the containers keep running the old code.
- **Every service restarts on its own** (`restart: unless-stopped`) after a crash or a VM reboot. Status: `docker compose -p luckyfive_kafka -f ai-stack.yml ps` (the API shows `healthy`). Logs: `… logs -f auth-detector` (or `api`, `filebeat`). Stop: `… down` (§9).
- **Coming from `start_all.sh`** (removed): stop its processes once, or the old uvicorn keeps port 8000 and the API container can't start — `pkill -f '/LuckyFive/ai-enhanced-xdr/ml-venv/bin/(uvicorn|python -u)'` (the full path, so the other group's processes are never matched). `demo_run.sh` does this for you.
- **Models:** the image has no PyTorch, so `auth-detector` and `web-detector` run Isolation Forest. Leave `DETECTOR_MODEL` unset (or `isolation_forest`); DFP runs live in `morpheus-auth`, and every model runs offline from the Morpheus env (§7).
- **Timestamps are UTC.** The `hour` feature and the "off-hours activity" category (before 06:00 or from 22:00) use UTC, matching the evaluation data — in Thailand that is before 13:00 or from 05:00. Run demos between 13:00 and 05:00 local, or quiet minutes get labelled off-hours.
- Check events reach Kafka: run this, then make any SSH login attempt on the VM. It prints one raw Wazuh event (JSON) or gives up after a minute:

      docker exec kafka /opt/kafka/bin/kafka-console-consumer.sh --bootstrap-server localhost:29092 --topic wazuh-archives --max-messages 1 --timeout-ms 60000

  Nothing → `docker logs luckyfive_kafka-filebeat-1`. Filebeat remembers how far it has read (the `filebeat_data` volume), so restarting it doesn't lose or replay events; its very first start begins at the end of today's archive, like the old producer.

## 6. Ollama (LLM explainer — R15)
- `curl -fsSL https://ollama.com/install.sh | sh`
- `ollama pull gemma3:12b` (9.2 GB resident; 80 GB VRAM fits far bigger if wanted)
- **Required:** cap the context, or model load dies with `CUDA error: unspecified launch failure` — Ollama defaults to the model's full 131072 tokens and reserves an 8.8 GB KV cache (failure log Entry 28):
  ```
  sudo mkdir -p /etc/systemd/system/ollama.service.d
  sudo tee /etc/systemd/system/ollama.service.d/override.conf <<'EOF'
  [Service]
  Environment="OLLAMA_CONTEXT_LENGTH=4096"
  EOF
  sudo systemctl daemon-reload && sudo systemctl restart ollama
  ```
- `.env`: `EXPLAINER_PROVIDER=ollama`, `OLLAMA_MODEL=gemma3:12b`; restart the API after editing
- verify without the stack: `python scripts/test_explainer.py mock ollama`
- confirm it is on the GPU: `ollama ps` → `100% GPU`

## 7. Morpheus (third model in the inference slot — R16)
`morpheus-core` links RAPIDS and the MRC C++ engine, so it is **conda-only** — it cannot go in `ml-venv`. The env is used two ways: imported, for DFP as a model (the comparison and evaluation scripts), and mounted read-only into the `morpheus-auth` service, which runs the SSH lane on Morpheus's pipeline runtime (§7b).

```
curl -fsSLo /tmp/miniforge.sh https://github.com/conda-forge/miniforge/releases/latest/download/Miniforge3-Linux-x86_64.sh
bash /tmp/miniforge.sh -b -p /LuckyFive/miniforge3          # NOT ~/, /home is 10 GB
/LuckyFive/miniforge3/bin/conda config --add pkgs_dirs /LuckyFive/miniforge3/pkgs
/LuckyFive/miniforge3/bin/conda config --add envs_dirs /LuckyFive/miniforge3/envs
source /LuckyFive/miniforge3/etc/profile.d/conda.sh
conda create -y -n morpheus python=3.12 && conda activate morpheus
conda config --env --add channels conda-forge && conda config --env --add channels nvidia
conda config --env --add channels rapidsai   && conda config --env --add channels pytorch
conda install -y -c nvidia morpheus-core=25.06
export TMPDIR=/LuckyFive/tmp PIP_CACHE_DIR=/LuckyFive/pip-cache   # or pip fills /tmp
MORPHEUS_CORE_PKG_DIR=$(dirname $(python -c "import morpheus; print(morpheus.__file__)"))
pip install -r ${MORPHEUS_CORE_PKG_DIR}/requirements_morpheus_core_arch-$(arch).txt
pip install pandas scikit-learn kafka-python-ng==2.2.3 opensearch-py==3.2.0 python-dotenv requests
```
Verify: `python -c "from morpheus.models.dfencoder import AutoEncoder; print('OK')"` and `python -c "import torch; print(torch.cuda.is_available())"`.

Run the three-model comparison (needs this env; the other two models run anywhere):
```
python scripts/compare_models.py --models isolation_forest,autoencoder,morpheus_dfencoder
```
The installs take ~25 min end to end; the conda solve is the slow part.

## 7b. The auth lane as a Morpheus pipeline (service `morpheus-auth`)
`ai-stack/morpheus/auth_pipeline.py` runs the SSH lane as an NVIDIA Morpheus pipeline — Kafka source → 1-minute windows → dfencoder on the GPU → OpenSearch — next to `auth-detector`, which stays as the CPU baseline. It has its own Kafka consumer group, so both see every event; its detections carry `ai.pipeline: "morpheus"`, and the console's Pipeline page lists it as `morpheus-auth`.

1. **Check the env** (no Kafka or OpenSearch needed) — want `ALL PASS`:

       conda activate morpheus && python ai-stack/morpheus/probe.py --cpu

2. **Run it** — it is a service in `ai-stack.yml`, so §5's `up -d --build` starts it with the rest. The container runs the conda env above, mounted read-only (`MORPHEUS_CONDA` in `ai-stack/.env`, default `/LuckyFive/miniforge3`), and gets the GPU through the NVIDIA container runtime (§1). Logs: `docker logs -f luckyfive_kafka-morpheus-auth-1`.

- **`--cpu`** is Morpheus's CPU mode for the dataframe stages (pandas). GPU mode (cuDF) crashes inside Morpheus's worker threads on this VM — driver 580 (CUDA 13) with the env's RAPIDS 25.02 (failure log Entry 41). dfencoder runs on the H100 either way; at a few hundred windows the dataframe work is trivial.
- **By hand instead** (foreground, for debugging): `python ai-stack/morpheus/auth_pipeline.py --cpu` in the env — stop the service first, or two Morpheus pipelines share one consumer group and Kafka splits the events between them.

## 8. Demo run and a real block

    bash scripts/demo_run.sh

Brings everything up, restarts the detectors and runs a scripted 15-minute SSH attack in the background (brute force at minute 6, spray at minute 9; `logs/attack.log` ends with `DONE`). Detections appear after about ten minutes. The attack comes from `::1`, which the console refuses to block. For a block that succeeds, attack from a container on its own Docker network — a private range nobody else uses, so the block touches nothing on the shared VM:

    docker network create --subnet 10.99.0.0/24 lf-attacker
    docker run --rm --network lf-attacker --ip 10.99.0.10 alpine:3.20 sh -c 'apk add -q --no-cache openssh-client && for i in $(seq 1 40); do for u in admin root; do ssh -o BatchMode=yes -o StrictHostKeyChecking=no -o ConnectTimeout=3 $u@10.99.0.1 true 2>/dev/null; done; done; echo done'

Block `10.99.0.10` from its rule 5712 alert or AI detection. Prove the drop (`REACHABLE` before, `NO RESPONSE (blocked)` after):

    docker run --rm --init --network lf-attacker --ip 10.99.0.10 alpine:3.20 sh -c 'nc -w 5 10.99.0.1 22 </dev/null && echo REACHABLE || echo "NO RESPONSE (blocked)"'

Clean up: remove the rule (§3b), then `docker network rm lf-attacker`.

## 9. When done
- `docker compose -p luckyfive_wazuh down` and `docker compose -p luckyfive_kafka -f ai-stack/ai-stack.yml down` — frees the shared box for the other group. The lab generator too, if running: `docker compose -p luckyfive_lab -f lab/docker-compose.yml down`. Access to this VM ends 30 Nov 2026.

## Later
What's next, and how it attaches: `docs/ROADMAP.md`.
