#!/usr/bin/env bash
# Back-to-back repeats of the encoder-config comparison in alternating order, to average out host noise.
cd "$(dirname "$0")/.."
python3 scripts/run.py --profile lan --scenario idle --config nocursor --tag lan_idle_nocursor --dur 30 --wait 30 --retries 1
for r in r2 r3; do
  for sc in scroll drag; do
    for cfg in base t1 noir fps120; do
      python3 scripts/run.py --profile lan --scenario $sc --config $cfg --tag lan_${sc}_${cfg}_$r --wait 30 --retries 1
    done
  done
done
