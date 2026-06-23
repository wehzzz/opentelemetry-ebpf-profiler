// SPDX-License-Identifier: BSD-2-Clause
//
// Port of plasma-umass/coz benchmarks/lock_test/lock_test.cpp (Curtsinger &
// Berger). Upstream: 4 worker threads each call critical_work() (under a
// global mutex) and local_work() (lock-free), then COZ_PROGRESS. Critical
// work is the bottleneck; local work is irrelevant.
//
// This C port:
//   - exposes `bench_progress`, `bench_critical_work`, `bench_local_work`
//     for uprobes;
//   - keeps the upstream topology exactly (4 workers, mutex on critical only);
//   - runs forever.
//
// Expected Coz finding: bench_critical_work has the highest slope (it is
// the scaling bottleneck); bench_local_work has slope near zero or
// negative.

#include <pthread.h>
#include <stdatomic.h>
#include <stdint.h>
#include <stdio.h>
#include <unistd.h>

enum { NumThreads = 4 };

static pthread_mutex_t the_lock = PTHREAD_MUTEX_INITIALIZER;
static volatile unsigned long long shared_counter;
static atomic_uint_fast64_t total_progress;

__attribute__((noinline)) void bench_progress(void)
{
  atomic_fetch_add_explicit(&total_progress, 1, memory_order_relaxed);
}

__attribute__((noinline)) void bench_critical_work(void)
{
  for (volatile int i = 0; i < 200000; i++) {
    shared_counter++;
  }
}

__attribute__((noinline)) void bench_local_work(void)
{
  volatile unsigned long long x = 0;
  for (volatile int i = 0; i < 200000; i++) {
    x++;
  }
}

static void *worker(void *arg)
{
  (void)arg;
  for (;;) {
    bench_local_work();
    pthread_mutex_lock(&the_lock);
    bench_critical_work();
    pthread_mutex_unlock(&the_lock);
    bench_progress();
  }
  return NULL;
}

int main(void)
{
  pthread_t t;
  for (int i = 0; i < NumThreads; i++) {
    if (pthread_create(&t, NULL, worker, NULL)) { perror("w"); return 1; }
    pthread_detach(t);
  }

  uint64_t previous = 0;
  for (;;) {
    sleep(1);
    uint64_t current = atomic_load_explicit(&total_progress, memory_order_relaxed);
    printf("progress_total=%llu progress_per_sec=%llu\n",
           (unsigned long long)current, (unsigned long long)(current - previous));
    previous = current;
    fflush(stdout);
  }
}
