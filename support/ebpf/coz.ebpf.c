#include "bpfdefs.h"

static u64 (*bpf_get_attach_cookie)(void *ctx) = (void *)BPF_FUNC_get_attach_cookie;

struct coz_counter_key {
  u32 experiment_id;
  u32 point_id;
};

struct coz_counter_value {
  u64 count;
};

struct coz_thread_state {
  u32 target_id;
  u32 depth;
  u64 entered_at_ns;
};

struct {
  __uint(type, BPF_MAP_TYPE_ARRAY);
  __type(key, u32);
  __type(value, u32);
  __uint(max_entries, 1);
} coz_active_experiment SEC(".maps");

struct {
  __uint(type, BPF_MAP_TYPE_PERCPU_HASH);
  __type(key, struct coz_counter_key);
  __type(value, struct coz_counter_value);
  __uint(max_entries, 4096);
} coz_progress_counts SEC(".maps");

struct {
  __uint(type, BPF_MAP_TYPE_LRU_HASH);
  __type(key, u64);
  __type(value, struct coz_thread_state);
  __uint(max_entries, 16384);
} coz_target_state SEC(".maps");

static EBPF_INLINE u32 active_experiment_id(void)
{
  u32 key = 0;
  u32 *id = bpf_map_lookup_elem(&coz_active_experiment, &key);
  if (!id) {
    return 0;
  }
  return *id;
}

SEC("uprobe/coz_progress")
int coz_progress(struct pt_regs *ctx)
{
  struct coz_counter_key key = {
    .experiment_id = active_experiment_id(),
    .point_id      = (u32)bpf_get_attach_cookie(ctx),
  };
  if (key.experiment_id == 0 || key.point_id == 0) {
    return 0;
  }

  struct coz_counter_value zero = {};
  struct coz_counter_value *value = bpf_map_lookup_elem(&coz_progress_counts, &key);
  if (!value) {
    bpf_map_update_elem(&coz_progress_counts, &key, &zero, BPF_NOEXIST);
    value = bpf_map_lookup_elem(&coz_progress_counts, &key);
  }
  if (value) {
    value->count++;
  }
  return 0;
}

SEC("uprobe/coz_target_enter")
int coz_target_enter(struct pt_regs *ctx)
{
  u64 pid_tgid = bpf_get_current_pid_tgid();
  u32 target_id = (u32)bpf_get_attach_cookie(ctx);
  if (target_id == 0) {
    return 0;
  }

  struct coz_thread_state zero = {};
  struct coz_thread_state *state = bpf_map_lookup_elem(&coz_target_state, &pid_tgid);
  if (!state) {
    bpf_map_update_elem(&coz_target_state, &pid_tgid, &zero, BPF_NOEXIST);
    state = bpf_map_lookup_elem(&coz_target_state, &pid_tgid);
  }
  if (state) {
    state->target_id     = target_id;
    state->depth++;
    state->entered_at_ns = bpf_ktime_get_ns();
  }
  return 0;
}

SEC("uprobe/coz_target_exit")
int coz_target_exit(struct pt_regs *ctx)
{
  u64 pid_tgid = bpf_get_current_pid_tgid();
  u32 target_id = (u32)bpf_get_attach_cookie(ctx);

  struct coz_thread_state *state = bpf_map_lookup_elem(&coz_target_state, &pid_tgid);
  if (!state || state->target_id != target_id || state->depth == 0) {
    return 0;
  }
  state->depth--;
  if (state->depth == 0) {
    bpf_map_delete_elem(&coz_target_state, &pid_tgid);
  }
  return 0;
}
