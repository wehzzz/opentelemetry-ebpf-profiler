# Coz Runner

Experimental Coz-like causal profiling runner.

## Build

```bash
make -C support/ebpf coz
go build -o /tmp/coz-runner ./tools/coz-runner
```

## Demo Workload

```bash
make -C tools/coz-demo
# producers=1, consumers=1, noise threads=4
./tools/coz-demo/coz-demo 1 1 4 &
PID=$!

sudo /tmp/coz-runner \
  -pid "$PID" \
  -progress "uprobe:$(pwd)/tools/coz-demo/coz-demo:coz_progress" \
  -target "uprobe:$(pwd)/tools/coz-demo/coz-demo:coz_hot" \
  -speedups 0,5,10,20,100 \
  -window 5s \
  -ptrace-quantum 10ms \
  -report /tmp/coz-report.json
```

`sudo` is usually required for eBPF and ptrace permissions.

### Topology

The demo is built so `coz_hot` is on the critical path of `coz_progress` via a
producer/consumer split:

- **Producer** threads run `coz_hot()` and push a unit into a bounded queue.
- **Consumer** threads block on the queue, then call `coz_progress()` — they
  are *not* runnable while waiting, so the ptrace backend will not perturb
  them.
- **Noise** threads do unrelated CPU work; they are the only runnable
  non-target threads available for perturbation.

This is the classic Coz setup: a virtual speedup of `coz_hot` is simulated by
stalling noise threads while `coz_hot` is executing, which frees CPU for the
producer. The expected slope on `coz_progress` throughput is positive or flat,
not negative — a negative slope on this workload would mean the perturbation
itself is dominating (try increasing `-ptrace-quantum`).

A single-threaded workload is still valid for observation, but the ptrace
backend deliberately skips perturbation when fewer than two non-target TIDs
are available to avoid turning a virtual speedup experiment into pure ptrace
overhead.

### Speedup semantics

Speedups are interpreted as in Coz:

- `0` — baseline (no perturbation).
- `1..99` — sampled perturbation. Per quantum, one runnable non-target TID is
  stopped for `quantum * s / (100 - s)`. The fraction of time non-target work
  is stalled approaches `s%`.
- `100` — full pause upper bound. Every quantum, threads that are not
  currently inside the target region are stopped; threads that re-enter the
  target are resumed. Equivalent to "the target runs alone whenever it is
  active". Use it to distinguish "target is not on the critical path"
  (throughput keeps dropping with `s`) from "the experiment is noisy"
  (throughput at `s=100` recovers or saturates).

The ptrace backend uses sampled perturbation for `s ∈ (0, 100)`: it perturbs
one runnable non-target TID per quantum in round-robin order. Increase
`-ptrace-quantum` if the report shows high `attempts` and lower throughput at
every speedup, and use `delayed_time_ns` to compare actual perturbation
intensity across runs.

## Coz Benchmarks

Build the Coz benchmark binary with symbols, then choose one progress function
and one target function from the symbol table:

```bash
nm -an ./benchmark | grep -E "progress|request|work|loop|transaction|handler"
```

Run the benchmark and attach the runner:

```bash
./benchmark &
PID=$!

sudo /tmp/coz-runner \
  -pid "$PID" \
  -progress "uprobe:/absolute/path/to/benchmark:<progress_symbol>" \
  -target "uprobe:/absolute/path/to/benchmark:<target_symbol>" \
  -speedups 0,5,10,20,100 \
  -window 10s \
  -report /tmp/coz-report.json
```
