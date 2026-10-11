#!/bin/bash
# Varied-intensity SSH attack for the demo recording.
#
# Last run used an identical burst every minute, so every window looked the
# same and the model had nothing to separate (scores ~0.0). This one gives it
# a real shape: quiet baseline minutes with light, varied failed logins, one
# sharp brute-force spike, one password-spray minute, then quiet again.
#
# Windows only exist for minutes that contain auth events, so baseline minutes
# still send a few attempts — that is what "normal" looks like to the model.
# Spike and spray land inside the first 10 windows, so the consumer's first
# scoring pass (at MIN_WINDOWS=10) already sees them.
#
# Runs ~15 minutes. Log: logs/attack.log

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"

attempt() {   # one failed login as user $1 (BatchMode = no prompt, fails instantly)
  ssh -o BatchMode=yes -o StrictHostKeyChecking=no -o ConnectTimeout=2 \
      "$1@localhost" true 2>/dev/null
}

baseline() {  # light noise: 1-3 attempts from 1-2 users
  local users=(alice bob carol)
  local n=$(( RANDOM % 3 + 1 ))
  for _ in $(seq 1 "$n"); do attempt "${users[$((RANDOM % 2))]}"; done
  echo "$(date +%H:%M:%S) baseline  ($n attempts)"
}

brute_force() {  # many attempts against very few accounts
  for _ in $(seq 1 40); do attempt admin; attempt root; done
  echo "$(date +%H:%M:%S) SPIKE     brute force (80 attempts, 2 users)"
}

spray() {  # one attempt each across many accounts
  for u in alice bob carol dave erin frank grace oracle postgres test deploy \
           git jenkins backup nginx svc mysql ftp www ubuntu; do attempt "$u"; done
  echo "$(date +%H:%M:%S) SPRAY     password spray (20 users, 1 attempt each)"
}

echo "demo attack started $(date)"
for minute in $(seq 1 15); do
  case $minute in
    6)  brute_force ;;
    9)  spray ;;
    *)  baseline ;;
  esac
  sleep 60
done
echo "DONE $(date)"
