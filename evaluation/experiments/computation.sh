#!/bin/bash

EVAL_SCRIPT="$(realpath "$(dirname "${BASH_SOURCE[0]}")")/../run-eval.sh"
if [ ! -f "$EVAL_SCRIPT" ]; then
    echo "Error: run-eval.sh missing!"
    exit 1
fi

mkdir -p results/computation/sgx
mkdir -p results/computation/baseline

for i in $(seq 1 35); do
    for reps in 10 100 1000 10000; do
        echo $i - $reps
        dir=$($EVAL_SCRIPT SGX seed-$i $reps | tail -n 1)
        mv $dir results/computation/sgx

        dir=$($EVAL_SCRIPT BASELINE seed-$i $reps | tail -n 1)
        mv $dir results/computation/baseline
    done
done

for t in results/computation/{sgx,baseline}; do
    for i in $t/*/eval-log.txt; do
        if grep -q 'completed!' $i; then
            echo -n "$(basename $t),"
            cat $i | grep -E 'time=|#responses' | sed 's/.*=//' | sed -z 's/\n/,/'
        fi
    done
done > results/computation/results.csv
