#!/usr/bin/env bash
# Constrained-profile runs plus the recovery test (netem removed 15 s into a 40 s window).
cd "$(dirname "$0")/.."
python3 scripts/matrix.py rtt50 rtt150 mobile
python3 scripts/run.py --profile rtt150-loss --scenario video --config base --tag recovery_rtt150-loss_video --dur 40 --clear-at 15 --wait 30 --retries 1
python3 scripts/run.py --profile rtt50 --scenario video --config base --tag recovery_rtt50_video --dur 40 --clear-at 15 --wait 30 --retries 1
echo constrained-done
