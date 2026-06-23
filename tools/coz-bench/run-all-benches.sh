#!/bin/bash
set -u
cd /home/bits/go/src/github.com/DataDog/opentelemetry-ebpf-profiler
BUDGET=${BUDGET:-120s}
for bench in useful_useless lockheavy coz_toy coz_pc coz_lock; do
  echo "================================================================"
  echo "### $bench (budget=$BUDGET)"
  echo "================================================================"
  /tmp/coz-verify \
    -bench "$bench" \
    -bench-dir ./tools/coz-bench \
    -runner /tmp/coz-runner \
    -bpf-object ./support/ebpf/coz.ebpf.amd64 \
    -budget "$BUDGET" \
    -report "/tmp/coz-verify-$bench.json" 2>&1 | tail -12
  echo
done
echo "ALL DONE"
