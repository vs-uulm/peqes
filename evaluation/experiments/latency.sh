#!/bin/bash

EVAL_SCRIPT="$(realpath "$(dirname "${BASH_SOURCE[0]}")")/../run-eval.sh"
if [ ! -f "$EVAL_SCRIPT" ]; then
    echo "Error: run-eval.sh missing!"
    exit 1
fi

mkdir -p results/latency

dir=$($EVAL_SCRIPT SGX latency 10000 | tail -n 1)
mv $dir results/latency/sgx

dir=$($EVAL_SCRIPT BASELINE latency 10000 | tail -n 1)
mv $dir results/latency/baseline

for t in results/latency/{sgx,baseline}; do
    cat $t/eval-log.txt | sed '1,/submit [0-9]* responses.../d' | sed '/[0-9]* responses submitted!/,$d' > $t/times.csv
done
