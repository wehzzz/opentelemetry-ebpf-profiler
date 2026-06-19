// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0
//go:build linux

package coz

import (
	"context"
	"errors"
	"fmt"
	"runtime"
	"time"
)

// TargetState is the userspace view of currently executing target regions.
type TargetState struct {
	ActiveTIDs map[int]ThreadState
}

// PerturbationBackend delays non-target work during speedup windows.
type PerturbationBackend interface {
	Attach(tids []int) error
	Apply(ctx context.Context, target func(context.Context) (TargetState, error), speedup int, duration time.Duration) (PerturbationStats, error)
	Detach() error
}

// TIDSource returns the thread IDs that are allowed to be perturbed.
type TIDSource interface {
	TIDs(pid int, maxThreads int) ([]int, error)
}

// Controller orchestrates one isolated causal profiling experiment.
type Controller struct {
	cfg          Config
	bpf          BPFProgramSet
	ptracer      PerturbationBackend
	tids         TIDSource
	deltas       *DeltaCounter
	windows      []WindowResult
	startedAt    time.Time
	roundsRun    int
	rotationSeed uint64
}

// NewController creates an experiment controller.
func NewController(cfg Config, bpf BPFProgramSet, ptracer PerturbationBackend, tids TIDSource) (*Controller, error) {
	cfg.Normalize()
	if err := cfg.Validate(); err != nil {
		return nil, err
	}
	if bpf == nil {
		bpf = noopBPF{}
	}
	if ptracer == nil {
		ptracer = noopPerturbation{}
	}
	if tids == nil {
		tids = procTIDSource{}
	}
	seed := cfg.RotationSeed
	if seed == 0 {
		seed = uint64(time.Now().UnixNano())
	}
	return &Controller{
		cfg:          cfg,
		bpf:          bpf,
		ptracer:      ptracer,
		tids:         tids,
		deltas:       NewDeltaCounter(),
		rotationSeed: seed,
	}, nil
}

func (c *Controller) Start(ctx context.Context) error {
	// Pin to an OS thread for the rest of this goroutine's life. ptrace
	// requires that every operation on a given tracee be issued by the same
	// tracer TID — without this lock, PtraceSeize runs on one OS thread and
	// the per-window PtraceInterrupt runs on another, giving ESRCH ("no
	// such process") and silently losing every perturbation. We do not pair
	// this with UnlockOSThread: the goroutine that owns the controller must
	// keep running on this thread until Close.
	runtime.LockOSThread()

	if err := c.bpf.Attach(ctx, c.cfg); err != nil {
		return fmt.Errorf("attach coz bpf programs: %w", err)
	}
	tids, err := c.tids.TIDs(c.cfg.PID, c.cfg.MaxThreads)
	if err != nil {
		_ = c.Close()
		return fmt.Errorf("enumerate tids for pid %d: %w", c.cfg.PID, err)
	}
	if err := c.ptracer.Attach(tids); err != nil {
		_ = c.Close()
		return fmt.Errorf("attach perturbation backend: %w", err)
	}
	c.startedAt = time.Now()
	return nil
}

// RunExperiment runs block-randomized rounds over the (target, speedup) cell
// pool until either the Rounds limit or Budget deadline trips. The current
// round is always finished to keep block-randomization sound. A partial report
// is written at the end of every round so an interrupted run still yields
// usable data.
func (c *Controller) RunExperiment(ctx context.Context) (*Report, error) {
	if c.startedAt.IsZero() {
		if err := c.Start(ctx); err != nil {
			return nil, err
		}
	}
	cells := BuildCells(c.cfg.Targets, c.cfg.Speedups)
	schedule := NewSchedule(cells, c.rotationSeed)

	var deadline time.Time
	if c.cfg.Budget > 0 {
		deadline = time.Now().Add(c.cfg.Budget)
	}

	lastTargetIdx := -1
	for round := 0; c.cfg.Rounds == 0 || round < c.cfg.Rounds; round++ {
		if !deadline.IsZero() && time.Now().After(deadline) {
			break
		}
		roundCells := schedule.Round()
		for _, cell := range roundCells {
			if err := ctx.Err(); err != nil {
				return c.finishReport(), err
			}
			if lastTargetIdx >= 0 && lastTargetIdx != cell.TargetIdx && c.cfg.Cooldown > 0 {
				if err := sleepContext(ctx, c.cfg.Cooldown); err != nil {
					return c.finishReport(), err
				}
			}
			lastTargetIdx = cell.TargetIdx

			window := Window{
				Phase:        PhaseForSpeedup(cell.Speedup),
				Speedup:      cell.Speedup,
				StartedAt:    time.Now(),
				ExperimentID: uint64(cell.ID),
				TargetIdx:    cell.TargetIdx,
			}
			window.EndsAt = window.StartedAt.Add(c.cfg.WindowDuration)
			result, err := c.runWindow(ctx, window)
			if err != nil {
				result.Errors = append(result.Errors, err.Error())
			}
			c.windows = append(c.windows, result)
			if err != nil {
				return c.finishReport(), err
			}
		}
		c.roundsRun = round + 1
		report := c.finishReport()
		if writeErr := WriteReport(c.cfg.ReportPath, report); writeErr != nil {
			return report, writeErr
		}
	}
	report := c.finishReport()
	if err := WriteReport(c.cfg.ReportPath, report); err != nil {
		return report, err
	}
	return report, nil
}

func (c *Controller) runWindow(ctx context.Context, window Window) (WindowResult, error) {
	experimentID := uint32(window.ExperimentID)
	target := c.cfg.Targets[window.TargetIdx]
	result := WindowResult{
		ExperimentID: window.ExperimentID,
		Phase:        window.Phase.String(),
		Speedup:      window.Speedup,
		StartedAt:    window.StartedAt,
		Duration:     c.cfg.WindowDuration,
		TargetIdx:    window.TargetIdx,
		TargetID:     target.ID,
		TargetName:   target.Name,
		Progress:     make(map[uint32]uint64),
		Throughput:   make(map[uint32]float64),
	}
	if err := c.bpf.SetActiveExperiment(ctx, experimentID); err != nil {
		return result, fmt.Errorf("set active experiment %d: %w", experimentID, err)
	}
	before, err := c.bpf.SnapshotProgress(ctx)
	if err != nil {
		return result, fmt.Errorf("snapshot progress before window: %w", err)
	}
	_ = c.deltas.Delta(before, experimentID)

	targetID := target.ID
	snapshot := func(snapCtx context.Context) (TargetState, error) {
		return c.snapshotTargetState(snapCtx, targetID)
	}

	applyStart := time.Now()
	stats, applyErr := c.ptracer.Apply(ctx, snapshot, window.Speedup, c.cfg.WindowDuration)
	result.Perturbation = stats
	result.Overhead.ApplyDuration = time.Since(applyStart)
	if applyErr != nil {
		return result, fmt.Errorf("apply perturbation: %w", applyErr)
	}

	snapshotStart := time.Now()
	after, err := c.bpf.SnapshotProgress(ctx)
	result.Overhead.SnapshotDuration = time.Since(snapshotStart)
	if err != nil {
		return result, fmt.Errorf("snapshot progress after window: %w", err)
	}
	result.Progress = c.deltas.Delta(after, experimentID)
	result.Throughput = throughput(result.Progress, c.cfg.WindowDuration)
	return result, nil
}

// snapshotTargetState filters the BPF target state to threads currently inside
// the given target ID. Other targets' executions are not relevant for this
// window's perturbation decisions.
func (c *Controller) snapshotTargetState(ctx context.Context, targetID uint32) (TargetState, error) {
	targets, err := c.bpf.SnapshotTargets(ctx)
	if err != nil {
		return TargetState{}, fmt.Errorf("snapshot targets: %w", err)
	}
	return targetStateForTarget(targets, targetID), nil
}

func (c *Controller) finishReport() *Report {
	startedAt := c.startedAt
	if startedAt.IsZero() {
		startedAt = time.Now()
	}
	report := newReport(c.cfg, c.rotationSeed, c.roundsRun, startedAt, c.windows)
	AnalyzeReport(report, defaultMinBaselineProg)
	return report
}

func (c *Controller) Close() error {
	return errors.Join(c.ptracer.Detach(), c.bpf.Close())
}

func sleepContext(ctx context.Context, d time.Duration) error {
	timer := time.NewTimer(d)
	defer timer.Stop()
	select {
	case <-ctx.Done():
		return ctx.Err()
	case <-timer.C:
		return nil
	}
}

type noopPerturbation struct{}

func (noopPerturbation) Attach([]int) error { return nil }
func (noopPerturbation) Apply(ctx context.Context, _ func(context.Context) (TargetState, error), _ int, d time.Duration) (PerturbationStats, error) {
	return PerturbationStats{}, sleepContext(ctx, d)
}
func (noopPerturbation) Detach() error { return nil }
