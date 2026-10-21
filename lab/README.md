# Lab test environment

The public dataset (AIT-LDS) gives the **web** lane its results (results_log R17)
but has almost no SSH activity and **no SSH attacks** (failure_log Entry 38). The
**SSH** lane — and web attack types AIT lacks (SQLi, XSS, traversal, HTTP
brute force) — are evaluated here, on our own environment with known ground truth.

An anomaly model learns "normal for *this* environment", so the lab is trained on
its own clean baseline, then tested on scripted attacks whose exact times we
record. Same protocol as AIT (train days 1–2, threshold day 3, test the attack
day); same feature code (`ai-stack/pipeline/features.py`).

## 1. Baseline — run this first, for ~3 days

`baseline/lab_baseline.py` writes genuine-format `auth.log` + `access.log` with
varied employee source IPs (10.20.0.0/24 — retires the old "everything from
127.0.0.1" limitation) and a work-hours rhythm. It writes log files only; it
opens no real connections.

Start it as a container (survives a reboot):

```bash
cd lab && docker compose -p luckyfive_lab up -d --build
docker logs -f luckyfive_lab-lab-baseline-1
```

Logs accumulate in `/LuckyFive/lab/logs/` (`auth.log`, `access.log`,
`meta.json`). Leave it running ~3 days. Keep it running during the attack days
too, so attacks land on top of normal traffic. Set `LAB_LOGS_DIR` in
`lab/.env` to use another directory.

Not waiting 3 days? Generate the baseline instantly instead (same content):

```bash
python baseline/lab_baseline.py --mode simulate --days 3 --out /LuckyFive/lab/logs
```

Direct run without Docker (no reboot-survival):

```bash
nohup python baseline/lab_baseline.py --mode realtime --out /LuckyFive/lab/logs &
```

## 2. Attacks

`lab/attacker/lab_attack.py` appends attack log lines onto one weekday in the
baseline (default: baseline start + 4 days) and writes `attack_schedule.csv`
(start, end, attacker IP, lane, type) — the ground truth. Attackers come from
10.20.9.0/24, distinct from the employees' 10.20.0.0/24. Pure stdlib.

```bash
python3 lab/attacker/lab_attack.py --logs /LuckyFive/lab/logs
```

It runs twelve attacks: web content-discovery scan, HTTP login brute force,
SQLi, XSS, path traversal; SSH brute force (fast + a night run), password spray,
distributed (10 IPs), and low-and-slow at 1/min, 1/3min, 1/6min (the
detection-floor sweep). Re-run with `--reset` to redo it (keeps the baseline).

## 3. Evaluate

`scripts/lab_windows.py` turns `auth.log` / `access.log` + `attack_schedule.csv`
into labelled 1-minute windows (same features as the live detectors), one CSV
per lane; `scripts/evaluate.py` then runs the R17 comparison (Isolation Forest
vs autoencoder vs Morpheus DFP, vs a count baseline). Run both in the `morpheus`
conda env (DFP needs it; the others run anywhere):

```bash
conda activate morpheus
python scripts/lab_windows.py --logs /LuckyFive/lab/logs --out /LuckyFive/eval
python scripts/evaluate.py /LuckyFive/eval/lab_*.csv --out /LuckyFive/eval/lab --train-days 3 --val-days 1
cat /LuckyFive/eval/lab/summary.md
```

`--train-days 3 --val-days 1`: train on the first 3 normal days, set the
threshold on day 4, test on the attack day (day 5) onward. The authoritative run
also replays the lab logs through Wazuh for genuine rule levels and the rule
baseline (failure_log Entry 40).

Note: scripted normal traffic is smoother than real users, so lab false-alarm
rates are optimistic — state this in the write-up (the "lab-only evaluation"
caveat; AIT's normal users are simulated too).
