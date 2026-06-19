// SPDX-License-Identifier: BSD-2-Clause
//
// Faithful reconstruction of the Coz signature demo (Curtsinger & Berger,
// "Coz: Finding Code that Counts with Causal Profiling", SOSP 2015, fig. 1 /
// plasma-umass/coz tests example pattern). We can't fetch tests/example1.cpp
// from upstream (it has moved between repository layouts), so this file
// reproduces the same conceptual workload using plain C + pthreads and
// exposes uprobe-attachable symbols.
//
// Workload:
//   - bench_useful_work() runs in a worker thread that, on completion, gates
//     a progress event. It IS on the critical path of progress.
//   - bench_useless_work() runs in a parallel thread that consumes CPU but
//     never produces progress.
//   - Both functions execute the same kind of CPU work (volatile counter
//     loop) so a flat CPU profile ranks them identically.
//
// Causal expectation (the entire raison d'être of Coz):
//   - virtual speedup of bench_useful_work   → positive slope (pausing the
//                                              useless thread frees CPU for
//                                              the useful one → progress up).
//   - virtual speedup of bench_useless_work  → negative or zero slope
//                                              (pausing the useful thread
//                                              slows down progress; pausing
//                                              the noise thread is free).
// The signal only materializes when the host is CPU-bound. Pin the process to
// fewer cores than active threads via `taskset -c 0,1` before attaching the
// runner if your machine has plenty of cores.

#include <pthread.h>
#include <semaphore.h>
#include <stdatomic.h>
#include <stdint.h>
#include <stdio.h>
#include <unistd.h>

static const uint64_t iters = 800000;

static atomic_uint_fast64_t total_progress;
static sem_t useful_done;

__attribute__((noinline)) void bench_progress(void)
{
  atomic_fetch_add_explicit(&total_progress, 1, memory_order_relaxed);
}

__attribute__((noinline)) void bench_useful_work(void)
{
  volatile uint64_t x = 0;
  for (uint64_t i = 0; i < iters; i++) {
    x++;
  }
}

__attribute__((noinline)) void bench_useless_work(void)
{
  volatile uint64_t y = 0;
  for (uint64_t i = 0; i < iters; i++) {
    y++;
  }
}

static void *useful_worker(void *arg)
{
  (void)arg;
  for (;;) {
    bench_useful_work();
    sem_post(&useful_done);
  }
  return NULL;
}

static void *useless_worker(void *arg)
{
  (void)arg;
  for (;;) {
    bench_useless_work();
  }
  return NULL;
}

static void *driver(void *arg)
{
  (void)arg;
  for (;;) {
    sem_wait(&useful_done);
    bench_progress();
  }
  return NULL;
}

int main(void)
{
  if (sem_init(&useful_done, 0, 0) != 0) {
    perror("sem_init");
    return 1;
  }
  pthread_t useful, useless, d;
  if (pthread_create(&useful, NULL, useful_worker, NULL) != 0) {
    perror("pthread_create useful");
    return 1;
  }
  pthread_detach(useful);
  if (pthread_create(&useless, NULL, useless_worker, NULL) != 0) {
    perror("pthread_create useless");
    return 1;
  }
  pthread_detach(useless);
  if (pthread_create(&d, NULL, driver, NULL) != 0) {
    perror("pthread_create driver");
    return 1;
  }
  pthread_detach(d);

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
