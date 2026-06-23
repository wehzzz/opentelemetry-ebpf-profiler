#include "vmlinux.h"
#include <bpf/bpf_core_read.h>
#include <bpf/bpf_helpers.h>

#define DSQ_SLOW 42

/* include/linux/sched/ext.h — sched_ext_entity.flags */
#ifndef SCX_TASK_QUEUED
#define SCX_TASK_QUEUED (1u << 0)
#endif

/* Max scx_bpf_dsq_move_to_local() attempts per dispatch() (backlog drain). */
#ifndef COZ_DISPATCH_MAX_MOVE
#define COZ_DISPATCH_MAX_MOVE 32u
#endif

#ifndef COZ_THROTTLE_LEVEL_MAX
#define COZ_THROTTLE_LEVEL_MAX 100u
#endif

struct {
  __uint(type, BPF_MAP_TYPE_HASH);
  __type(key, u32);
  __type(value, u32);
  __uint(max_entries, 4096);
} coz_throttle_set SEC(".maps");

struct {
  __uint(type, BPF_MAP_TYPE_ARRAY);
  __type(key, u32);
  __type(value, u32);
  __uint(max_entries, 1);
} coz_target_active SEC(".maps");

struct {
  __uint(type, BPF_MAP_TYPE_HASH);
  __type(key, u32);
  __type(value, u64);
  __uint(max_entries, 4096);
  __uint(map_flags, BPF_F_NO_PREALLOC);
} coz_duty_acc SEC(".maps");

SEC("struct_ops/enqueue")
void enqueue(struct task_struct *p, u64 enq_flags)
{
  u32 key0 = 0;
  u32 tid  = BPF_CORE_READ(p, pid);

  u32 *active   = bpf_map_lookup_elem(&coz_target_active, &key0);
  u32 *throttle = bpf_map_lookup_elem(&coz_throttle_set, &tid);
  if (!active || *active == 0 || !throttle || *throttle == 0) {
    scx_bpf_dsq_insert(p, SCX_DSQ_LOCAL, SCX_SLICE_DFL, enq_flags);
    return;
  }

  u64 *acc = bpf_map_lookup_elem(&coz_duty_acc, &tid);
  if (!acc) {
    u64 zero = 0;
    bpf_map_update_elem(&coz_duty_acc, &tid, &zero, BPF_NOEXIST);
    acc = bpf_map_lookup_elem(&coz_duty_acc, &tid);
    if (!acc) {
      scx_bpf_dsq_insert(p, SCX_DSQ_LOCAL, SCX_SLICE_DFL, enq_flags);
      return;
    }
  }

  u32 th = *throttle;
  if (th > COZ_THROTTLE_LEVEL_MAX) {
    th = COZ_THROTTLE_LEVEL_MAX;
  }
  u64 lv   = (u64)th;
  u64 prev = __atomic_fetch_add(acc, lv, __ATOMIC_RELAXED);
  u64 next = prev + lv;
  if ((prev / 100u) != (next / 100u)) {
    scx_bpf_dsq_insert(p, DSQ_SLOW, SCX_SLICE_DFL / 4, enq_flags);
    return;
  }
  scx_bpf_dsq_insert(p, SCX_DSQ_LOCAL, SCX_SLICE_DFL, enq_flags);
}

SEC("struct_ops/dispatch")
void dispatch(s32 cpu, struct task_struct *prev)
{
  (void)cpu;

  /*
   * kernel/sched/ext: if @prev is still runnable (SCX_TASK_QUEUED), it is not
   * enqueued yet and will be after dispatch returns — do not pull other work
   * onto the local DSQ if we want @prev to keep running.
   */
  if (prev) {
    u32 scx_flags = BPF_CORE_READ(prev, scx.flags);
    if (scx_flags & SCX_TASK_QUEUED) {
      return;
    }
  }

  /*
   * scx_bpf_dsq_move_to_local(dsq_id, enq_flags): v2 kfunc (e.g. 6.13+). Pass 0
   * for enq_flags unless you OR in SCX_ENQ_* intentionally.
   */
  u32 n;
  for (n = 0; n < COZ_DISPATCH_MAX_MOVE; n++) {
    if (!scx_bpf_dsq_move_to_local(DSQ_SLOW, 0)) {
      break;
    }
  }
}

SEC("struct_ops.s/init")
s32 init(void)
{
  return scx_bpf_create_dsq(DSQ_SLOW, -1);
}

SEC("struct_ops/exit")
void exit(struct scx_exit_info *info)
{
  (void)info;
  scx_bpf_destroy_dsq(DSQ_SLOW);
}

SEC(".struct_ops.link")
struct sched_ext_ops coz_sched_ops = {
  .enqueue  = (void *)enqueue,
  .dispatch = (void *)dispatch,
  .init     = (void *)init,
  .exit     = (void *)exit,
  .name     = "coz_sched",
};