// SPDX-License-Identifier: BSD-2-Clause
//
// Minimal repro of the scaling-bottleneck pattern Coz identifies in its
// benchmarks/pbzip2 and benchmarks/lock_test case studies (Curtsinger &
// Berger, SOSP 2015, §6.2). The original benchmark is heavy and externally
// sourced; we keep the essential structure — a globally-serialized critical
// section forces N worker threads into single-file execution while a parallel
// section runs lock-free — and expose plain C symbols so the runner can
// auto-pick targets via uprobes.
//
// Anchors in performance-patterns:
//   - patterns/ttas.md       — fix candidate for a TTAS-shaped spinlock
//   - patterns/mutex-to-rwlock.md — fix candidate when read-only critical
//                                   sections are common (not used here).
//
// Causal expectation on a CPU-bound host (pin to ≤ N cores via taskset):
//   - virtual speedup of bench_serialized_step  → positive slope.
//     Pausing the noise thread (and the other workers' lock-free work) frees
//     CPU for the lock holder, shortening the time it spends inside the
//     mutex → next worker acquires sooner → throughput up.
//   - virtual speedup of bench_parallel_step    → near-zero or negative slope.
//     Workers can do bench_parallel_step concurrently; pausing peers does
//     not help, only hurts their throughput.
//   - virtual speedup of bench_noise_work       → strongly negative slope.
//     Noise is pure CPU competition; pausing workers slows everything.

#include <pthread.h>
#include <stdatomic.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>

#define WORKER_COUNT 4
#define NOISE_COUNT  1

static const uint64_t serialized_iters = 200000;
static const uint64_t parallel_iters = 200000;
static const uint64_t noise_iters = 400000;

static pthread_mutex_t global_lock = PTHREAD_MUTEX_INITIALIZER;
static volatile uint64_t shared_state;

static atomic_uint_fast64_t total_progress;

__attribute__((noinline)) void bench_progress(void)
{
  atomic_fetch_add_explicit(&total_progress, 1, memory_order_relaxed);
}

__attribute__((noinline)) void bench_serialized_step(void)
{
  pthread_mutex_lock(&global_lock);
  volatile uint64_t local = shared_state;
  for (uint64_t i = 0; i < serialized_iters; i++) {
    local = (local * 1103515245u + 12345u + i) ^ (local >> 7);
  }
  shared_state = local;
  pthread_mutex_unlock(&global_lock);
}

__attribute__((noinline)) void bench_parallel_step(void)
{
  volatile uint64_t local = 0;
  for (uint64_t i = 0; i < parallel_iters; i++) {
    local = local * 6364136223846793005ULL + 1442695040888963407ULL;
  }
}

__attribute__((noinline)) void bench_noise_work(void)
{
  volatile uint64_t local = 1;
  for (uint64_t i = 0; i < noise_iters; i++) {
    local = local * 2862933555777941757ULL + 3037000493ULL;
  }
}

static void *worker(void *arg)
{
  (void)arg;
  for (;;) {
    bench_serialized_step();
    bench_parallel_step();
    bench_progress();
  }
  return NULL;
}

static void *noise(void *arg)
{
  (void)arg;
  for (;;) {
    bench_noise_work();
  }
  return NULL;
}

int main(void)
{
  pthread_t tid;
  for (int i = 0; i < WORKER_COUNT; i++) {
    if (pthread_create(&tid, NULL, worker, NULL) != 0) {
      perror("pthread_create worker");
      return 1;
    }
    pthread_detach(tid);
  }
  for (int i = 0; i < NOISE_COUNT; i++) {
    if (pthread_create(&tid, NULL, noise, NULL) != 0) {
      perror("pthread_create noise");
      return 1;
    }
    pthread_detach(tid);
  }

  uint64_t previous = 0;
  for (;;) {
    sleep(1);
    uint64_t current = atomic_load_explicit(&total_progress, memory_order_relaxed);
    printf("progress_total=%llu progress_per_sec=%llu\n",
           (unsigned long long)current,
           (unsigned long long)(current - previous));
    previous = current;
    fflush(stdout);
  }
}
