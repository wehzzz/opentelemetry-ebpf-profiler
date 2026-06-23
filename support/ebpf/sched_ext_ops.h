/* SPDX-License-Identifier: GPL-2.0 WITH Linux-syscall-note */
/*
 * struct sched_ext_ops for BPF sources in this tree.
 *
 * Upstream lives in kernel/sched/ext_internal.h (sched_ext). We vendor it here
 * because support/ebpf/kernel.h intentionally avoids full kernel headers, so
 * clang/clangd otherwise only see a forward declaration and error on:
 *   "Variable has incomplete type 'struct sched_ext_ops'".
 *
 * Sync: torvalds/linux master — refresh when targeting a kernel whose
 * sched_ext_ops layout diverges (check CONFIG_EXT_GROUP_SCHED too).
 */
#ifndef OPTI_SCHED_EXT_OPS_H
#define OPTI_SCHED_EXT_OPS_H

#include "kernel.h"

#ifndef __rcu
#define __rcu
#endif

#ifndef SCX_OPS_NAME_LEN
#define SCX_OPS_NAME_LEN 128
#endif

/*
 * Kernels built with CONFIG_EXT_GROUP_SCHED=n omit the cgroup_* op pointers.
 * Most distro configs enable it; if your load fails struct_ops BTF matching,
 * align this with your kernel's include/linux/sched/ext.h / ext_internal.h.
 */
#ifndef CONFIG_EXT_GROUP_SCHED
#define CONFIG_EXT_GROUP_SCHED 1
#endif

struct cgroup;
struct cpumask;
struct scx_init_task_args;
struct scx_exit_task_args;
struct scx_cpu_acquire_args;
struct scx_cpu_release_args;
struct scx_dump_ctx;
struct scx_exit_info;
struct scx_sub_attach_args;
struct scx_sub_detach_args;
struct scx_cgroup_init_args;

struct sched_ext_ops {
  /**
   * @select_cpu: Pick the target CPU for a task which is being woken up
   * @p: task being woken up
   * @prev_cpu: the cpu @p was on before sleeping
   * @wake_flags: SCX_WAKE_*
   *
   * Decision made here isn't final. @p may be moved to any CPU while it
   * is getting dispatched for execution later. However, as @p is not on
   * the rq at this point, getting the eventual execution CPU right here
   * saves a small bit of overhead down the line.
   *
   * If an idle CPU is returned, the CPU is kicked and will try to
   * dispatch. While an explicit custom mechanism can be added,
   * select_cpu() serves as the default way to wake up idle CPUs.
   *
   * @p may be inserted into a DSQ directly by calling
   * scx_bpf_dsq_insert(). If so, the ops.enqueue() will be skipped.
   * Directly inserting into %SCX_DSQ_LOCAL will put @p in the local DSQ
   * of the CPU returned by this operation.
   *
   * Note that select_cpu() is never called for tasks that can only run
   * on a single CPU or tasks with migration disabled, as they don't have
   * the option to select a different CPU. See select_task_rq() for
   * details.
   */
  s32 (*select_cpu)(struct task_struct *p, s32 prev_cpu, u64 wake_flags);

  /**
   * @enqueue: Enqueue a task on the BPF scheduler
   * @p: task being enqueued
   * @enq_flags: %SCX_ENQ_*
   *
   * @p is ready to run. Insert directly into a DSQ by calling
   * scx_bpf_dsq_insert() or enqueue on the BPF scheduler. If not directly
   * inserted, the bpf scheduler owns @p and if it fails to dispatch @p,
   * the task will stall.
   *
   * If @p was inserted into a DSQ from ops.select_cpu(), this callback is
   * skipped.
   */
  void (*enqueue)(struct task_struct *p, u64 enq_flags);

  /**
   * @dequeue: Remove a task from the BPF scheduler
   * @p: task being dequeued
   * @deq_flags: %SCX_DEQ_*
   *
   * Remove @p from the BPF scheduler. This is usually called to isolate
   * the task while updating its scheduling properties (e.g. priority).
   *
   * The ext core keeps track of whether the BPF side owns a given task or
   * not and can gracefully ignore spurious dispatches from BPF side,
   * which makes it safe to not implement this method. However, depending
   * on the scheduling logic, this can lead to confusing behaviors - e.g.
   * scheduling position not being updated across a priority change.
   */
  void (*dequeue)(struct task_struct *p, u64 deq_flags);

  /**
   * @dispatch: Dispatch tasks from the BPF scheduler and/or user DSQs
   * @cpu: CPU to dispatch tasks for
   * @prev: previous task being switched out
   *
   * Called when a CPU's local dsq is empty. The operation should dispatch
   * one or more tasks from the BPF scheduler into the DSQs using
   * scx_bpf_dsq_insert() and/or move from user DSQs into the local DSQ
   * using scx_bpf_dsq_move_to_local().
   *
   * The maximum number of times scx_bpf_dsq_insert() can be called
   * without an intervening scx_bpf_dsq_move_to_local() is specified by
   * ops.dispatch_max_batch. See the comments on top of the two functions
   * for more details.
   *
   * When not %NULL, @prev is an SCX task with its slice depleted. If
   * @prev is still runnable as indicated by set %SCX_TASK_QUEUED in
   * @prev->scx.flags, it is not enqueued yet and will be enqueued after
   * ops.dispatch() returns. To keep executing @prev, return without
   * dispatching or moving any tasks. Also see %SCX_OPS_ENQ_LAST.
   */
  void (*dispatch)(s32 cpu, struct task_struct *prev);

  /**
   * @tick: Periodic tick
   * @p: task running currently
   *
   * This operation is called every 1/HZ seconds on CPUs which are
   * executing an SCX task. Setting @p->scx.slice to 0 will trigger an
   * immediate dispatch cycle on the CPU.
   */
  void (*tick)(struct task_struct *p);

  /**
   * @runnable: A task is becoming runnable on its associated CPU
   * @p: task becoming runnable
   * @enq_flags: %SCX_ENQ_*
   *
   * This and the following three functions can be used to track a task's
   * execution state transitions. A task becomes ->runnable() on a CPU,
   * and then goes through one or more ->running() and ->stopping() pairs
   * as it runs on the CPU, and eventually becomes ->quiescent() when it's
   * done running on the CPU.
   *
   * @p is becoming runnable on the CPU because it's
   *
   * - waking up (%SCX_ENQ_WAKEUP)
   * - being moved from another CPU
   * - being restored after temporarily taken off the queue for an
   *   attribute change.
   *
   * This and ->enqueue() are related but not coupled. This operation
   * notifies @p's state transition and may not be followed by ->enqueue()
   * e.g. when @p is being dispatched to a remote CPU, or when @p is
   * being enqueued on a CPU experiencing a hotplug event. Likewise, a
   * task may be ->enqueue()'d without being preceded by this operation
   * e.g. after exhausting its slice.
   */
  void (*runnable)(struct task_struct *p, u64 enq_flags);

  /**
   * @running: A task is starting to run on its associated CPU
   * @p: task starting to run
   *
   * Note that this callback may be called from a CPU other than the
   * one the task is going to run on. This can happen when a task
   * property is changed (i.e., affinity), since scx_next_task_scx(),
   * which triggers this callback, may run on a CPU different from
   * the task's assigned CPU.
   *
   * Therefore, always use scx_bpf_task_cpu(@p) to determine the
   * target CPU the task is going to use.
   *
   * See ->runnable() for explanation on the task state notifiers.
   */
  void (*running)(struct task_struct *p);

  /**
   * @stopping: A task is stopping execution
   * @p: task stopping to run
   * @runnable: is task @p still runnable?
   *
   * Note that this callback may be called from a CPU other than the
   * one the task was running on. This can happen when a task
   * property is changed (i.e., affinity), since dequeue_task_scx(),
   * which triggers this callback, may run on a CPU different from
   * the task's assigned CPU.
   *
   * Therefore, always use scx_bpf_task_cpu(@p) to retrieve the CPU
   * the task was running on.
   *
   * See ->runnable() for explanation on the task state notifiers. If
   * !@runnable, ->quiescent() will be invoked after this operation
   * returns.
   */
  void (*stopping)(struct task_struct *p, bool runnable);

  /**
   * @quiescent: A task is becoming not runnable on its associated CPU
   * @p: task becoming not runnable
   * @deq_flags: %SCX_DEQ_*
   *
   * See ->runnable() for explanation on the task state notifiers.
   *
   * @p is becoming quiescent on the CPU because it's
   *
   * - sleeping (%SCX_DEQ_SLEEP)
   * - being moved to another CPU
   * - being temporarily taken off the queue for an attribute change
   *   (%SCX_DEQ_SAVE)
   *
   * This and ->dequeue() are related but not coupled. This operation
   * notifies @p's state transition and may not be preceded by ->dequeue()
   * e.g. when @p is being dispatched to a remote CPU.
   */
  void (*quiescent)(struct task_struct *p, u64 deq_flags);

  /**
   * @yield: Yield CPU
   * @from: yielding task
   * @to: optional yield target task
   *
   * If @to is NULL, @from is yielding the CPU to other runnable tasks.
   * The BPF scheduler should ensure that other available tasks are
   * dispatched before the yielding task. Return value is ignored in this
   * case.
   *
   * If @to is not-NULL, @from wants to yield the CPU to @to. If the bpf
   * scheduler can implement the request, return %true; otherwise, %false.
   */
  bool (*yield)(struct task_struct *from, struct task_struct *to);

  /**
   * @core_sched_before: Task ordering for core-sched
   * @a: task A
   * @b: task B
   *
   * Used by core-sched to determine the ordering between two tasks. See
   * Documentation/admin-guide/hw-vuln/core-scheduling.rst for details on
   * core-sched.
   *
   * Both @a and @b are runnable and may or may not currently be queued on
   * the BPF scheduler. Should return %true if @a should run before @b.
   * %false if there's no required ordering or @b should run before @a.
   *
   * If not specified, the default is ordering them according to when they
   * became runnable.
   */
  bool (*core_sched_before)(struct task_struct *a, struct task_struct *b);

  /**
   * @set_weight: Set task weight
   * @p: task to set weight for
   * @weight: new weight [1..10000]
   *
   * Update @p's weight to @weight.
   */
  void (*set_weight)(struct task_struct *p, u32 weight);

  /**
   * @set_cpumask: Set CPU affinity
   * @p: task to set CPU affinity for
   * @cpumask: cpumask of cpus that @p can run on
   *
   * Update @p's CPU affinity to @cpumask.
   */
  void (*set_cpumask)(struct task_struct *p,
          const struct cpumask *cpumask);

  /**
   * @update_idle: Update the idle state of a CPU
   * @cpu: CPU to update the idle state for
   * @idle: whether entering or exiting the idle state
   *
   * This operation is called when @rq's CPU goes or leaves the idle
   * state. By default, implementing this operation disables the built-in
   * idle CPU tracking and the following helpers become unavailable:
   *
   * - scx_bpf_select_cpu_dfl()
   * - scx_bpf_select_cpu_and()
   * - scx_bpf_test_and_clear_cpu_idle()
   * - scx_bpf_pick_idle_cpu()
   *
   * The user also must implement ops.select_cpu() as the default
   * implementation relies on scx_bpf_select_cpu_dfl().
   *
   * Specify the %SCX_OPS_KEEP_BUILTIN_IDLE flag to keep the built-in idle
   * tracking.
   */
  void (*update_idle)(s32 cpu, bool idle);

  /**
   * @init_task: Initialize a task to run in a BPF scheduler
   * @p: task to initialize for BPF scheduling
   * @args: init arguments, see the struct definition
   *
   * Either we're loading a BPF scheduler or a new task is being forked.
   * Initialize @p for BPF scheduling. This operation may block and can
   * be used for allocations, and is called exactly once for a task.
   *
   * Return 0 for success, -errno for failure. An error return while
   * loading will abort loading of the BPF scheduler. During a fork, it
   * will abort that specific fork.
   */
  s32 (*init_task)(struct task_struct *p, struct scx_init_task_args *args);

  /**
   * @exit_task: Exit a previously-running task from the system
   * @p: task to exit
   * @args: exit arguments, see the struct definition
   *
   * @p is exiting or the BPF scheduler is being unloaded. Perform any
   * necessary cleanup for @p.
   */
  void (*exit_task)(struct task_struct *p, struct scx_exit_task_args *args);

  /**
   * @enable: Enable BPF scheduling for a task
   * @p: task to enable BPF scheduling for
   *
   * Enable @p for BPF scheduling. enable() is called on @p any time it
   * enters SCX, and is always paired with a matching disable().
   */
  void (*enable)(struct task_struct *p);

  /**
   * @disable: Disable BPF scheduling for a task
   * @p: task to disable BPF scheduling for
   *
   * @p is exiting, leaving SCX or the BPF scheduler is being unloaded.
   * Disable BPF scheduling for @p. A disable() call is always matched
   * with a prior enable() call.
   */
  void (*disable)(struct task_struct *p);

  /**
   * @dump: Dump BPF scheduler state on error
   * @ctx: debug dump context
   *
   * Use scx_bpf_dump() to generate BPF scheduler specific debug dump.
   */
  void (*dump)(struct scx_dump_ctx *ctx);

  /**
   * @dump_cpu: Dump BPF scheduler state for a CPU on error
   * @ctx: debug dump context
   * @cpu: CPU to generate debug dump for
   * @idle: @cpu is currently idle without any runnable tasks
   *
   * Use scx_bpf_dump() to generate BPF scheduler specific debug dump for
   * @cpu. If @idle is %true and this operation doesn't produce any
   * output, @cpu is skipped for dump.
   */
  void (*dump_cpu)(struct scx_dump_ctx *ctx, s32 cpu, bool idle);

  /**
   * @dump_task: Dump BPF scheduler state for a runnable task on error
   * @ctx: debug dump context
   * @p: runnable task to generate debug dump for
   *
   * Use scx_bpf_dump() to generate BPF scheduler specific debug dump for
   * @p.
   */
  void (*dump_task)(struct scx_dump_ctx *ctx, struct task_struct *p);

#ifdef CONFIG_EXT_GROUP_SCHED
  /**
   * @cgroup_init: Initialize a cgroup
   * @cgrp: cgroup being initialized
   * @args: init arguments, see the struct definition
   *
   * Either the BPF scheduler is being loaded or @cgrp created, initialize
   * @cgrp for sched_ext. This operation may block.
   *
   * Return 0 for success, -errno for failure. An error return while
   * loading will abort loading of the BPF scheduler. During cgroup
   * creation, it will abort the specific cgroup creation.
   */
  s32 (*cgroup_init)(struct cgroup *cgrp,
         struct scx_cgroup_init_args *args);

  /**
   * @cgroup_exit: Exit a cgroup
   * @cgrp: cgroup being exited
   *
   * Either the BPF scheduler is being unloaded or @cgrp destroyed, exit
   * @cgrp for sched_ext. This operation my block.
   */
  void (*cgroup_exit)(struct cgroup *cgrp);

  /**
   * @cgroup_prep_move: Prepare a task to be moved to a different cgroup
   * @p: task being moved
   * @from: cgroup @p is being moved from
   * @to: cgroup @p is being moved to
   *
   * Prepare @p for move from cgroup @from to @to. This operation may
   * block and can be used for allocations.
   *
   * Return 0 for success, -errno for failure. An error return aborts the
   * migration.
   */
  s32 (*cgroup_prep_move)(struct task_struct *p,
        struct cgroup *from, struct cgroup *to);

  /**
   * @cgroup_move: Commit cgroup move
   * @p: task being moved
   * @from: cgroup @p is being moved from
   * @to: cgroup @p is being moved to
   *
   * Commit the move. @p is dequeued during this operation.
   */
  void (*cgroup_move)(struct task_struct *p,
          struct cgroup *from, struct cgroup *to);

  /**
   * @cgroup_cancel_move: Cancel cgroup move
   * @p: task whose cgroup move is being canceled
   * @from: cgroup @p was being moved from
   * @to: cgroup @p was being moved to
   *
   * @p was cgroup_prep_move()'d but failed before reaching cgroup_move().
   * Undo the preparation.
   */
  void (*cgroup_cancel_move)(struct task_struct *p,
           struct cgroup *from, struct cgroup *to);

  /**
   * @cgroup_set_weight: A cgroup's weight is being changed
   * @cgrp: cgroup whose weight is being updated
   * @weight: new weight [1..10000]
   *
   * Update @cgrp's weight to @weight.
   */
  void (*cgroup_set_weight)(struct cgroup *cgrp, u32 weight);

  /**
   * @cgroup_set_bandwidth: A cgroup's bandwidth is being changed
   * @cgrp: cgroup whose bandwidth is being updated
   * @period_us: bandwidth control period
   * @quota_us: bandwidth control quota
   * @burst_us: bandwidth control burst
   *
   * Update @cgrp's bandwidth control parameters. This is from the cpu.max
   * cgroup interface.
   *
   * @quota_us / @period_us determines the CPU bandwidth @cgrp is entitled
   * to. For example, if @period_us is 1_000_000 and @quota_us is
   * 2_500_000. @cgrp is entitled to 2.5 CPUs. @burst_us can be
   * interpreted in the same fashion and specifies how much @cgrp can
   * burst temporarily. The specific control mechanism and thus the
   * interpretation of @period_us and burstiness is up to the BPF
   * scheduler.
   */
  void (*cgroup_set_bandwidth)(struct cgroup *cgrp,
             u64 period_us, u64 quota_us, u64 burst_us);

  /**
   * @cgroup_set_idle: A cgroup's idle state is being changed
   * @cgrp: cgroup whose idle state is being updated
   * @idle: whether the cgroup is entering or exiting idle state
   *
   * Update @cgrp's idle state to @idle. This callback is invoked when
   * a cgroup transitions between idle and non-idle states, allowing the
   * BPF scheduler to adjust its behavior accordingly.
   */
  void (*cgroup_set_idle)(struct cgroup *cgrp, bool idle);

#endif  /* CONFIG_EXT_GROUP_SCHED */

  /**
   * @sub_attach: Attach a sub-scheduler
   * @args: argument container, see the struct definition
   *
   * Return 0 to accept the sub-scheduler. -errno to reject.
   */
  s32 (*sub_attach)(struct scx_sub_attach_args *args);

  /**
   * @sub_detach: Detach a sub-scheduler
   * @args: argument container, see the struct definition
   */
  void (*sub_detach)(struct scx_sub_detach_args *args);

  /*
   * All online ops must come before ops.cpu_online().
   */

  /**
   * @cpu_online: A CPU became online
   * @cpu: CPU which just came up
   *
   * @cpu just came online. @cpu will not call ops.enqueue() or
   * ops.dispatch(), nor run tasks associated with other CPUs beforehand.
   */
  void (*cpu_online)(s32 cpu);

  /**
   * @cpu_offline: A CPU is going offline
   * @cpu: CPU which is going offline
   *
   * @cpu is going offline. @cpu will not call ops.enqueue() or
   * ops.dispatch(), nor run tasks associated with other CPUs afterwards.
   */
  void (*cpu_offline)(s32 cpu);

  /*
   * All CPU hotplug ops must come before ops.init().
   */

  /**
   * @init: Initialize the BPF scheduler
   */
  s32 (*init)(void);

  /**
   * @exit: Clean up after the BPF scheduler
   * @info: Exit info
   *
   * ops.exit() is also called on ops.init() failure, which is a bit
   * unusual. This is to allow rich reporting through @info on how
   * ops.init() failed.
   */
  void (*exit)(struct scx_exit_info *info);

  /*
   * Data fields must comes after all ops fields.
   */

  /**
   * @dispatch_max_batch: Max nr of tasks that dispatch() can dispatch
   */
  u32 dispatch_max_batch;

  /**
   * @flags: %SCX_OPS_* flags
   */
  u64 flags;

  /**
   * @timeout_ms: The maximum amount of time, in milliseconds, that a
   * runnable task should be able to wait before being scheduled. The
   * maximum timeout may not exceed the default timeout of 30 seconds.
   *
   * Defaults to the maximum allowed timeout value of 30 seconds.
   */
  u32 timeout_ms;

  /**
   * @exit_dump_len: scx_exit_info.dump buffer length. If 0, the default
   * value of 32768 is used.
   */
  u32 exit_dump_len;

  /**
   * @hotplug_seq: A sequence number that may be set by the scheduler to
   * detect when a hotplug event has occurred during the loading process.
   * If 0, no detection occurs. Otherwise, the scheduler will fail to
   * load if the sequence number does not match @scx_hotplug_seq on the
   * enable path.
   */
  u64 hotplug_seq;

  /**
   * @cgroup_id: When >1, attach the scheduler as a sub-scheduler on the
   * specified cgroup.
   */
  u64 sub_cgroup_id;

  /**
   * @name: BPF scheduler's name
   *
   * Must be a non-zero valid BPF object name including only isalnum(),
   * '_' and '.' chars. Shows up in kernel.sched_ext_ops sysctl while the
   * BPF scheduler is enabled.
   */
  char name[SCX_OPS_NAME_LEN];

  /* internal use only, must be NULL */
  void __rcu *priv;

  /*
   * Deprecated callbacks. Kept at the end of the struct so the cid-form
   * struct (sched_ext_ops_cid) can omit them without affecting the
   * shared field offsets. Use SCX_ENQ_IMMED instead. Sitting past
   * SCX_OPI_END means has_op doesn't cover them, so SCX_HAS_OP() cannot
   * be used; callers must test sch->ops.cpu_acquire / cpu_release
   * directly.
   */

  /**
   * @cpu_acquire: A CPU is becoming available to the BPF scheduler
   * @cpu: The CPU being acquired by the BPF scheduler.
   * @args: Acquire arguments, see the struct definition.
   *
   * A CPU that was previously released from the BPF scheduler is now once
   * again under its control. Deprecated; use SCX_ENQ_IMMED instead.
   */
  void (*cpu_acquire)(s32 cpu, struct scx_cpu_acquire_args *args);

  /**
   * @cpu_release: A CPU is taken away from the BPF scheduler
   * @cpu: The CPU being released by the BPF scheduler.
   * @args: Release arguments, see the struct definition.
   *
   * The specified CPU is no longer under the control of the BPF
   * scheduler. This could be because it was preempted by a higher
   * priority sched_class, though there may be other reasons as well. The
   * caller should consult @args->reason to determine the cause.
   * Deprecated; use SCX_ENQ_IMMED instead.
   */
  void (*cpu_release)(s32 cpu, struct scx_cpu_release_args *args);
};

#endif /* OPTI_SCHED_EXT_OPS_H */
