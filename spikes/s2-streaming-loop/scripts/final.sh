#!/usr/bin/env bash
# Final LAN runs with the final server binary: default config and the recommended low-pacing config.
cd "$(dirname "$0")/.."
for sc in typing scroll drag video; do
  for cfg in base fps120; do
    python3 scripts/run.py --profile lan --scenario $sc --config $cfg --tag final_lan_${sc}_${cfg} --wait 30 --retries 2
  done
done
echo final-done
