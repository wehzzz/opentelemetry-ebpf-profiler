// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

//go:build linux

package coz

import (
	"context"
	"errors"
	"fmt"
	"os"
	"runtime"
	"sort"
	"sync"
	"time"

	"golang.org/x/sys/unix"
)

const defaultPerturbationQuantum = 10 * time.Millisecond

// PtraceBackend perturbs individual TIDs with ptrace.
type PtraceBackend struct {
	quantum time.Duration

	mu       sync.Mutex
	attached map[int]struct{}
	nextTID  int
}

func NewPtraceBackend(quantum time.Duration) *PtraceBackend {
	if quantum <= 0 {
		quantum = defaultPerturbationQuantum
	}
	return &PtraceBackend{
		quantum:  quantum,
		attached: make(map[int]struct{}),
	}
}

func (p *PtraceBackend) Attach(tids []int) error {
	p.mu.Lock()
	defer p.mu.Unlock()
	if p.attached == nil {
		p.attached = make(map[int]struct{})
	}
	var joined error
	for _, tid := range tids {
		if _, exists := p.attached[tid]; exists {
			continue
		}
		if err := unix.PtraceSeize(tid); err != nil {
			joined = errors.Join(joined, fmt.Errorf("ptrace seize tid %d: %w", tid, err))
			continue
		}
		p.attached[tid] = struct{}{}
	}
	if len(p.attached) == 0 && joined != nil {
		return joined
	}
	return joined
}

func (p *PtraceBackend) Apply(ctx context.Context, target func(context.Context) (TargetState, error), speedup int, duration time.Duration) (PerturbationStats, error) {
	if speedup == 0 {
		return PerturbationStats{}, sleepContext(ctx, duration)
	}
	if speedup == 100 {
		return p.applyFullPause(ctx, target, duration)
	}
	stats := PerturbationStats{}
	end := time.Now().Add(duration)
	delay := p.delayForSpeedup(speedup)
	runtime.LockOSThread()
	defer runtime.UnlockOSThread()
	for time.Now().Before(end) {
		select {
		case <-ctx.Done():
			stats.Invalidated = true
			return stats, ctx.Err()
		default:
		}
		targetState, err := target(ctx)
		if err != nil {
			stats.Invalidated = true
			return stats, err
		}
		tids := p.nonTargetTIDs(targetState)
		if len(tids) == 0 {
			if err := sleepContext(ctx, p.quantum); err != nil {
				stats.Invalidated = true
				return stats, err
			}
			continue
		}
		tid := p.pickTID(tids)
		stats.Attempts++
		if err := interruptAndDelay(ctx, tid, delay); err != nil {
			stats.Failures++
			if isThreadGone(err) {
				p.forget(tid)
				continue
			}
			stats.Invalidated = true
			return stats, err
		}
		stats.DelayedThreads++
		stats.DelayedTime += delay
		if err := sleepContext(ctx, p.quantum); err != nil {
			stats.Invalidated = true
			return stats, err
		}
	}
	return stats, nil
}

// applyFullPause models the speedup=100 upper bound: any thread that is not
// currently inside the target region is stopped, and is resumed as soon as it
// enters the target. The target state is resampled every quantum so producer
// threads that briefly leave the target between iterations are not stalled for
// the entire window.
//
// Bounded at duration/quantum * attached_tids ptrace ops worst case.
func (p *PtraceBackend) applyFullPause(ctx context.Context, target func(context.Context) (TargetState, error), duration time.Duration) (PerturbationStats, error) {
	stats := PerturbationStats{}
	end := time.Now().Add(duration)
	paused := make(map[int]time.Time)

	resumeAll := func() {
		now := time.Now()
		for tid, since := range paused {
			stats.DelayedTime += now.Sub(since)
			if err := unix.PtraceCont(tid, 0); err != nil && !isThreadGone(err) {
				stats.Failures++
			}
			delete(paused, tid)
		}
	}

	for time.Now().Before(end) {
		if err := ctx.Err(); err != nil {
			resumeAll()
			stats.Invalidated = true
			return stats, err
		}
		targetState, err := target(ctx)
		if err != nil {
			resumeAll()
			stats.Invalidated = true
			return stats, err
		}
		now := time.Now()
		for tid, since := range paused {
			if _, active := targetState.ActiveTIDs[tid]; active {
				stats.DelayedTime += now.Sub(since)
				if err := unix.PtraceCont(tid, 0); err != nil && !isThreadGone(err) {
					stats.Failures++
				}
				delete(paused, tid)
			}
		}
		for _, tid := range p.nonTargetTIDs(targetState) {
			if _, already := paused[tid]; already {
				continue
			}
			stats.Attempts++
			if err := interruptAndWait(tid); err != nil {
				stats.Failures++
				if isThreadGone(err) {
					p.forget(tid)
				}
				continue
			}
			stats.DelayedThreads++
			paused[tid] = time.Now()
		}
		if err := sleepContext(ctx, p.quantum); err != nil {
			resumeAll()
			stats.Invalidated = true
			return stats, err
		}
	}
	resumeAll()
	return stats, nil
}

func (p *PtraceBackend) Detach() error {
	p.mu.Lock()
	defer p.mu.Unlock()
	var joined error
	for tid := range p.attached {
		if err := stopAndDetach(tid); err != nil {
			joined = errors.Join(joined, fmt.Errorf("ptrace detach tid %d: %w", tid, err))
		}
		delete(p.attached, tid)
	}
	return joined
}

func (p *PtraceBackend) nonTargetTIDs(target TargetState) []int {
	p.mu.Lock()
	defer p.mu.Unlock()
	tids := make([]int, 0, len(p.attached))
	for tid := range p.attached {
		if _, active := target.ActiveTIDs[tid]; active {
			continue
		}
		if !isRunnable(tid) {
			continue
		}
		tids = append(tids, tid)
	}
	sort.Ints(tids)
	return tids
}

func (p *PtraceBackend) pickTID(tids []int) int {
	p.mu.Lock()
	defer p.mu.Unlock()
	idx := p.nextTID % len(tids)
	p.nextTID++
	return tids[idx]
}

func (p *PtraceBackend) forget(tid int) {
	p.mu.Lock()
	defer p.mu.Unlock()
	delete(p.attached, tid)
}

func (p *PtraceBackend) delayForSpeedup(speedup int) time.Duration {
	if speedup <= 0 {
		return 0
	}
	delay := time.Duration(speedup) * p.quantum / time.Duration(100-speedup)
	if delay <= 0 {
		return time.Microsecond
	}
	return delay
}

func interruptAndDelay(ctx context.Context, tid int, delay time.Duration) error {
	if err := interruptAndWait(tid); err != nil {
		return err
	}
	if err := sleepContext(ctx, delay); err != nil {
		_ = unix.PtraceCont(tid, 0)
		return err
	}
	if err := unix.PtraceCont(tid, 0); err != nil {
		return fmt.Errorf("ptrace continue tid %d: %w", tid, err)
	}
	return nil
}

func interruptAndWait(tid int) error {
	if err := unix.PtraceInterrupt(tid); err != nil {
		return fmt.Errorf("ptrace interrupt tid %d: %w", tid, err)
	}
	var status unix.WaitStatus
	if _, err := unix.Wait4(tid, &status, 0, nil); err != nil {
		_ = unix.PtraceCont(tid, 0)
		return fmt.Errorf("wait interrupted tid %d: %w", tid, err)
	}
	if !status.Stopped() {
		_ = unix.PtraceCont(tid, 0)
		return fmt.Errorf("tid %d did not enter ptrace stop: %v", tid, status)
	}
	return nil
}

func stopAndDetach(tid int) error {
	if err := unix.PtraceInterrupt(tid); err != nil {
		if errors.Is(err, unix.ESRCH) {
			return nil
		}
		return fmt.Errorf("interrupt before detach: %w", err)
	}
	var status unix.WaitStatus
	if _, err := unix.Wait4(tid, &status, 0, nil); err != nil {
		if errors.Is(err, unix.ECHILD) || errors.Is(err, unix.ESRCH) {
			return nil
		}
		return fmt.Errorf("wait before detach: %w", err)
	}
	if err := unix.PtraceDetach(tid); err != nil && !errors.Is(err, unix.ESRCH) {
		return err
	}
	return nil
}

func isThreadGone(err error) bool {
	return errors.Is(err, unix.ESRCH) || errors.Is(err, unix.ECHILD)
}

func isRunnable(tid int) bool {
	state, err := procThreadState(tid)
	return err == nil && state == 'R'
}

func procThreadState(tid int) (byte, error) {
	return parseProcThreadState(fmt.Sprintf("/proc/%d/stat", tid))
}

func parseProcThreadState(path string) (byte, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return 0, err
	}
	for i := len(data) - 1; i >= 0; i-- {
		if data[i] == ')' {
			if i+2 >= len(data) {
				return 0, fmt.Errorf("malformed proc stat %q", path)
			}
			return data[i+2], nil
		}
	}
	return 0, fmt.Errorf("malformed proc stat %q", path)
}
