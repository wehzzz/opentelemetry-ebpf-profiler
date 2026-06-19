// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0
//go:build linux

package coz

import (
	"context"
	"errors"
	"fmt"
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
	cfg       Config
	bpf       BPFProgramSet
	ptracer   PerturbationBackend
	tids      TIDSource
	deltas    *DeltaCounter
	windows   []WindowResult
	startedAt time.Time
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
	return &Controller{
		cfg:     cfg,
		bpf:     bpf,
		ptracer: ptracer,
		tids:    tids,
		deltas:  NewDeltaCounter(),
	}, nil
}

func (c *Controller) Start(ctx context.Context) error {
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

// RunExperiment runs all configured windows and writes the JSON report.
func (c *Controller) RunExperiment(ctx context.Context) (*Report, error) {
	if c.startedAt.IsZero() {
		if err := c.Start(ctx); err != nil {
			return nil, err
		}
	}
	for idx, speedup := range c.cfg.Speedups {
		phase := PhaseSpeedup
		if speedup == 0 {
			phase = PhaseBaseline
		}
		window := Window{
			Phase:        phase,
			Speedup:      speedup,
			StartedAt:    time.Now(),
			ExperimentID: uint64(idx + 1),
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
		if c.cfg.Cooldown > 0 {
			if err := sleepContext(ctx, c.cfg.Cooldown); err != nil {
				return c.finishReport(), err
			}
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
	result := WindowResult{
		ExperimentID: window.ExperimentID,
		Phase:        window.Phase.String(),
		Speedup:      window.Speedup,
		StartedAt:    window.StartedAt,
		Duration:     c.cfg.WindowDuration,
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

	applyStart := time.Now()
	stats, applyErr := c.ptracer.Apply(ctx, c.snapshotTargetState, window.Speedup, c.cfg.WindowDuration)
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

func (c *Controller) snapshotTargetState(ctx context.Context) (TargetState, error) {
	targets, err := c.bpf.SnapshotTargets(ctx)
	if err != nil {
		return TargetState{}, fmt.Errorf("snapshot targets: %w", err)
	}
	return targetStateFromTID(targets), nil
}

func (c *Controller) finishReport() *Report {
	startedAt := c.startedAt
	if startedAt.IsZero() {
		startedAt = time.Now()
	}
	return newReport(c.cfg, startedAt, c.windows)
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
