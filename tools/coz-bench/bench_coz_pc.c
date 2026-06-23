// SPDX-License-Identifier: BSD-2-Clause
//
// Port of plasma-umass/coz benchmarks/producer_consumer/producer_consumer.cpp
// (Curtsinger & Berger). Upstream: 5 producers / 3 consumers / bounded queue
// of size 10, mutex + 3 condvars, COZ_PROGRESS in consumer.
//
// This C port:
//   - exposes `bench_progress` (called by consumer) and two target candidates
//     `bench_producer_step` (the producer's per-item work) and
//     `bench_consumer_step` (the consumer's per-item work);
//   - runs forever (no fixed Items cap, so the controller can keep attaching);
//   - keeps the upstream queue / mutex / condvar topology exactly.
//
// Expected Coz finding (from the Coz paper): the producer is the bottleneck
// when queue stays empty most of the time. bench_producer_step should rank
// higher than bench_consumer_step.

#include <pthread.h>
#include <stdatomic.h>
#include <stdint.h>
#include <stdio.h>
#include <unistd.h>

enum {
  ProducerCount = 5,
  ConsumerCount = 3,
  QueueSize     = 10,
};

static int produced = 0;
static int consumed = 0;
static int queue_count = 0;

static pthread_mutex_t queue_lock = PTHREAD_MUTEX_INITIALIZER;
static pthread_cond_t  producer_cv = PTHREAD_COND_INITIALIZER;
static pthread_cond_t  consumer_cv = PTHREAD_COND_INITIALIZER;

static atomic_uint_fast64_t total_progress;

__attribute__((noinline)) void bench_progress(void)
{
  atomic_fetch_add_explicit(&total_progress, 1, memory_order_relaxed);
}

__attribute__((noinline)) void bench_producer_step(void)
{
  // Simulate per-item work (matches upstream's tight produce loop body).
  volatile uint64_t x = 0;
  for (uint64_t i = 0; i < 100000; i++) x++;
}

__attribute__((noinline)) void bench_consumer_step(void)
{
  // Slightly less work per item — keeps consumers faster than producers,
  // so producers gate progress.
  volatile uint64_t x = 0;
  for (uint64_t i = 0; i < 30000; i++) x++;
}

static void *producer(void *arg)
{
  (void)arg;
  for (;;) {
    bench_producer_step();
    pthread_mutex_lock(&queue_lock);
    while (queue_count == QueueSize) {
      pthread_cond_wait(&producer_cv, &queue_lock);
    }
    queue_count++;
    produced++;
    pthread_mutex_unlock(&queue_lock);
    pthread_cond_signal(&consumer_cv);
  }
  return NULL;
}

static void *consumer(void *arg)
{
  (void)arg;
  for (;;) {
    pthread_mutex_lock(&queue_lock);
    while (queue_count == 0) {
      pthread_cond_wait(&consumer_cv, &queue_lock);
    }
    queue_count--;
    consumed++;
    pthread_mutex_unlock(&queue_lock);
    pthread_cond_signal(&producer_cv);
    bench_consumer_step();
    bench_progress();
  }
  return NULL;
}

int main(void)
{
  pthread_t t;
  for (int i = 0; i < ProducerCount; i++) {
    if (pthread_create(&t, NULL, producer, NULL)) { perror("p"); return 1; }
    pthread_detach(t);
  }
  for (int i = 0; i < ConsumerCount; i++) {
    if (pthread_create(&t, NULL, consumer, NULL)) { perror("c"); return 1; }
    pthread_detach(t);
  }

  uint64_t previous = 0;
  for (;;) {
    sleep(1);
    uint64_t current = atomic_load_explicit(&total_progress, memory_order_relaxed);
    printf("progress_total=%llu progress_per_sec=%llu produced=%d consumed=%d\n",
           (unsigned long long)current, (unsigned long long)(current - previous),
           produced, consumed);
    previous = current;
    fflush(stdout);
  }
}
