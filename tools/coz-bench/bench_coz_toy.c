// SPDX-License-Identifier: BSD-2-Clause
//
// Port of plasma-umass/coz benchmarks/toy/toy.cpp (Curtsinger & Berger,
// Coz paper §3.1, fig. 1). Upstream creates two threads per iteration that
// run a() and b() respectively, joins both, then COZ_PROGRESS. The longer
// thread a() is on the critical path; b() is the second-longest leg.
//
// This C port:
//   - replaces pthread_create/join-per-iteration (slow) with semaphore
//     coordination so we get hundreds of progress events per 500 ms window,
//   - exposes `bench_progress`, `bench_a`, `bench_b` symbols for uprobes,
//   - runs forever so the controller can attach.
//
// Expected Coz ranking: bench_a > bench_b (a is the longer leg and gates
// the join; b finishes early and idles).

#include <pthread.h>
#include <semaphore.h>
#include <stdatomic.h>
#include <stdint.h>
#include <stdio.h>
#include <unistd.h>

static const uint64_t a_iters = 400000;
static const uint64_t b_iters = 200000;

static atomic_uint_fast64_t total_progress;
static sem_t a_start, a_done, b_start, b_done;

__attribute__((noinline)) void bench_progress(void)
{
  atomic_fetch_add_explicit(&total_progress, 1, memory_order_relaxed);
}

__attribute__((noinline)) void bench_a(void)
{
  volatile uint64_t x = 0;
  for (uint64_t i = 0; i < a_iters; i++) {
    x++;
  }
}

__attribute__((noinline)) void bench_b(void)
{
  volatile uint64_t y = 0;
  for (uint64_t i = 0; i < b_iters; i++) {
    y++;
  }
}

static void *thread_a(void *arg) { (void)arg; for (;;) { sem_wait(&a_start); bench_a(); sem_post(&a_done); } }
static void *thread_b(void *arg) { (void)arg; for (;;) { sem_wait(&b_start); bench_b(); sem_post(&b_done); } }

static void *driver(void *arg)
{
  (void)arg;
  for (;;) {
    sem_post(&a_start);
    sem_post(&b_start);
    sem_wait(&a_done);
    sem_wait(&b_done);
    bench_progress();
  }
  return NULL;
}

int main(void)
{
  if (sem_init(&a_start, 0, 0) || sem_init(&a_done, 0, 0)
      || sem_init(&b_start, 0, 0) || sem_init(&b_done, 0, 0)) { perror("sem_init"); return 1; }
  pthread_t t;
  if (pthread_create(&t, NULL, thread_a, NULL)) { perror("a"); return 1; } pthread_detach(t);
  if (pthread_create(&t, NULL, thread_b, NULL)) { perror("b"); return 1; } pthread_detach(t);
  if (pthread_create(&t, NULL, driver, NULL))   { perror("d"); return 1; } pthread_detach(t);

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
