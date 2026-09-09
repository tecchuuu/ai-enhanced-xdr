# SETUP — running on the SIAM AI VM

Overall flow. Assumes you know `git clone` + `pip install -r requirements.txt`.
Only the non-obvious / SIAM-specific steps are spelled out.

## What's different on this box
- **Shared Docker daemon** (2 groups per VM) → one Docker service runs both groups' containers; your *directory does not isolate you*. Name clashes are unlikely (different projects) but possible if both groups use the official `wazuh-docker` (both default to project `single-node`). Cheap insurance: prefix compose commands with `-p LuckyFive_wazuh` / `-p LuckyFive_kafka` (optional, not mandatory). **What actually matters: take turns + `compose down` when done** — host ports (:443, :9200, :8000) can only bind once on a shared VM, and `-p` does NOT fix that.
- **Shared hardware** → keep everything in Docker; `docker compose down` when you stop (removes containers, so nothing lingers on reboot).
- **No Claude API key here** → the LLM explainer runs on **Ollama** (local model on the H100), not Anthropic.
- **Secrets (`.env`) are NOT in git** → recreate on this box (step 4).

## 1. System (sudo, once)
- `sudo apt install -y git python3-venv python3-pip curl`
- Docker (official repo) + **NVIDIA Container Toolkit**; add user to `docker` group; `sudo nvidia-ctk runtime configure && sudo systemctl restart docker`
- Kernel param before Wazuh: `sudo sysctl -w vm.max_map_count=262144`
- Verify GPU in a container: `docker run --rm --gpus all nvidia/cuda:12.4.0-base-ubuntu22.04 nvidia-smi`

## 2. Project + venv
- `git clone <repo> && cd ai-enhanced-xdr`
- `python3 -m venv ml-venv && ml-venv/bin/pip install -r requirements.txt`
- Optional — the autoencoder model (`DETECTOR_MODEL=autoencoder`) needs PyTorch, kept out of `requirements.txt` so the base install stays light: `ml-venv/bin/pip install torch` (the default Linux build is CUDA-enabled → uses the H100). Isolation Forest needs no torch.

## 3. Wazuh stack
- `cd wazuh && docker compose -p LuckyFive_wazuh up -d`  (`-p` optional; namespaces your containers)
- Change the admin password: `hash.sh` → put hash in `internal_users.yml` → recreate indexer → `securityadmin.sh -f ... -t internalusers`. (See failure_log for the exact sequence + the bind-mount gotcha.)

## 4. .env (secrets — not in git)
    cp dashboard/.env.example dashboard/.env
Set: `OS_HOST=localhost`, `OS_PORT=9200`, `OS_USER=admin`, `OS_PASS=<the pw from step 3>`,
`EXPLAINER_PROVIDER=ollama`, `OLLAMA_MODEL=llama3.2` (no ANTHROPIC key),
`WAZUH_CONTAINER=LuckyFive_wazuh-wazuh.manager-1` (must match your `-p` name so the producer tails YOUR manager, never the other group's).

## 5. Kafka + pipeline
- `docker compose -p LuckyFive_kafka -f ai-stack/ai-stack.yml up -d`
- `./ai-stack/start_all.sh`  (uvicorn + producer + consumer, via nohup)

## 6. Ollama (LLM explainer — fills report §4.8)
- `curl -fsSL https://ollama.com/install.sh | sh`
- `ollama pull llama3.2`  (a 70B fits in 80GB VRAM if you want bigger)
- explainer picks it up via `EXPLAINER_PROVIDER=ollama`; restart the API after editing `.env`

## 7. When done
- `docker compose -p LuckyFive_wazuh down` and `docker compose -p LuckyFive_kafka -f ai-stack/ai-stack.yml down` — frees the shared box for the other group.

## Later (stretch, unpredictable — budget multi-day each)
- **Morpheus on H100** (DFP, Kafka-native source) — real throughput numbers for the report.
- **DPU network lane** — Suricata on BlueField-3 → EVE JSON → separate Kafka consumer + model.
