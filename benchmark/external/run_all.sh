#!/bin/bash
# Run every configuration on each dataset: accuracy once on all documents,
# then speed three times on a fixed sample of each (the results report the
# median). DATASETS picks some (default: ylemis indiapii corpus). One run at a time, so timings do not compete.
#
# Needs: python fetch_data.py; setup_envs.sh (one environment per other tool);
# PYTHON pointing to a Python with credgate's dependencies (credgate itself is
# taken from this repository's pkg/python/src).
set -u
HERE=$(cd "$(dirname "$0")" && pwd)
REPO=$(cd "$HERE/../.." && pwd)
E=$HERE/envs
PYTHON=${PYTHON:-python3}
DATASETS=${DATASETS:-ylemis indiapii corpus}
cd "$HERE"
mkdir -p runs/timing

run() { # dataset config input output
  local ds=$1 cfg=$2 in=$3 out=$4 py t x=() iso=-I env=()
  case $cfg in
    credgate) py=$PYTHON; t=credgate; iso=""; env=(PYTHONPATH="$REPO/pkg/python/src");;
    credgate-0.5) py=$PYTHON; t=credgate; x=(--min-confidence 0.5); iso=""; env=(PYTHONPATH="$REPO/pkg/python/src");;
    credgate-names-0.5) py=$PYTHON; t=credgate-names; x=(--min-confidence 0.5); iso=""; env=(PYTHONPATH="$REPO/pkg/python/src");;
    presidio*) py=$E/presidio/bin/python; t=$cfg;;
    *) py=$E/$cfg/bin/python; t=$cfg;;
  esac
  env ${env[@]+"${env[@]}"} "$py" $iso adapter.py "$t" "$in" "$out" ${x[@]+"${x[@]}"} 2>"${out%.jsonl}.err" >/dev/null \
    || echo "FAILED $ds $cfg"
}

CONFIGS="credgate credgate-0.5 credgate-names-0.5 kavach maskflow presidio presidio-india"
for ds in $DATASETS; do
  for cfg in $CONFIGS; do
    echo "$(date +%T) accuracy $ds $cfg"
    run "$ds" "$cfg" "data/$ds.docs.jsonl" "runs/$ds.$cfg.jsonl"
  done
done
for rep in 1 2 3; do
  for ds in $DATASETS; do
    for cfg in $CONFIGS; do
      echo "$(date +%T) timing $rep $ds $cfg"
      run "$ds" "$cfg" "data/$ds.timing.jsonl" "runs/timing/$ds.$cfg.$rep.jsonl"
    done
  done
done
echo "$(date +%T) done"
