// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

// Demo workload for the experimental Coz-like controller.
//
// Topology:
//   - producer threads run coz_hot() and post a unit into a bounded queue
//   - consumer threads block on the queue, then call coz_progress()
//   - noise threads do unrelated CPU work and act as perturbation targets
//
// Goal: coz_hot is on the critical path of coz_progress (consumers starve
// without producer output), while consumers sleep on the semaphore — so the
// only runnable non-target threads available for ptrace perturbation are the
// noise threads. A virtual speedup of coz_hot should then produce a positive
// slope on coz_progress throughput.

#include <stdint.h>
#include <stdatomic.h>
#include <stdio.h>
#include <stdlib.h>
#include <pthread.h>
#include <semaphore.h>
#include <unistd.h>

#define QUEUE_CAPACITY 16

static volatile uint64_t producer_sink;
static volatile uint64_t noise_sink;
static atomic_uint_fast64_t total_progress;

static sem_t queue_slots;
static sem_t queue_items;

__attribute__((noinline)) void coz_progress(void)
{
  atomic_fetch_add_explicit(&total_progress, 1, memory_order_relaxed);
}

__attribute__((noinline)) void coz_hot(void)
{
  uint64_t local = producer_sink;
  for (uint64_t i = 0; i < 200000; i++) {
    local = (local * 1103515245u + 12345u + i) ^ (local >> 7);
  }
  producer_sink = local;
}

static void *producer(void *arg)
{
  (void)arg;
  for (;;) {
    sem_wait(&queue_slots);
    coz_hot();
    sem_post(&queue_items);
  }
  return NULL;
}

static void *consumer(void *arg)
{
  (void)arg;
  for (;;) {
    sem_wait(&queue_items);
    coz_progress();
    sem_post(&queue_slots);
  }
  return NULL;
}

static void *noise(void *arg)
{
  uint64_t local = (uint64_t)(uintptr_t)arg;
  for (;;) {
    for (uint64_t i = 0; i < 200000; i++) {
      local = local * 6364136223846793005ULL + 1442695040888963407ULL;
    }
    noise_sink = local;
  }
  return NULL;
}

static int positive_arg(const char *s, int fallback)
{
  int v = atoi(s);
  return (v > 0) ? v : fallback;
}

int main(int argc, char **argv)
{
  int producers = 1;
  int consumers = 1;
  int noises = 4;
  if (argc > 1) producers = positive_arg(argv[1], producers);
  if (argc > 2) consumers = positive_arg(argv[2], consumers);
  if (argc > 3) noises = (atoi(argv[3]) >= 0) ? atoi(argv[3]) : noises;

  if (sem_init(&queue_slots, 0, QUEUE_CAPACITY) != 0) {
    perror("sem_init slots");
    return 1;
  }
  if (sem_init(&queue_items, 0, 0) != 0) {
    perror("sem_init items");
    return 1;
  }

  pthread_t t;
  for (int i = 0; i < producers; i++) {
    if (pthread_create(&t, NULL, producer, NULL) != 0) {
      perror("pthread_create producer");
      return 1;
    }
    pthread_detach(t);
  }
  for (int i = 0; i < consumers; i++) {
    if (pthread_create(&t, NULL, consumer, NULL) != 0) {
      perror("pthread_create consumer");
      return 1;
    }
    pthread_detach(t);
  }
  for (int i = 0; i < noises; i++) {
    if (pthread_create(&t, NULL, noise, (void *)(uintptr_t)(i + 1)) != 0) {
      perror("pthread_create noise");
      return 1;
    }
    pthread_detach(t);
  }

  uint64_t previous = 0;
  for (;;) {
    sleep(1);
    uint64_t current = atomic_load_explicit(&total_progress, memory_order_relaxed);
    printf("progress_total=%llu progress_per_sec=%llu producers=%d consumers=%d noise=%d\n",
           (unsigned long long)current,
           (unsigned long long)(current - previous),
           producers, consumers, noises);
    previous = current;
    fflush(stdout);
  }
  return 0;
}
