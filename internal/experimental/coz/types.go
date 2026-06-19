// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0
//go:build linux

// Package coz contains an experimental Coz-like causal profiling controller.
//
// The package is intentionally isolated from the production profiling pipeline:
// progress events are counted through lightweight eBPF maps and reported as a
// local JSON artifact instead of flowing through stack trace reporting.
package coz

import (
	"errors"
	"fmt"
	"time"

	"go.opentelemetry.io/ebpf-profiler/tracer"
)

const (
	defaultWindowDuration = 10 * time.Second
	defaultCooldown       = time.Second
	defaultMaxThreads     = 256
	defaultReportPath     = "coz-report.json"
)

var (
	errMissingPID      = errors.New("pid must be positive")
	errMissingProgress = errors.New("at least one progress point is required")
	errMissingTarget   = errors.New("at least one target is required")
)

// Config describes one causal profiling run.
type Config struct {
	Enabled        bool
	PID            int
	ProgressPoints []ProbePoint
	Targets        []TargetPoint
	Speedups       []int
	WindowDuration time.Duration
	Cooldown       time.Duration
	MaxThreads     int
	ReportPath     string
	OverheadBudget OverheadBudget
}

// ProbePoint identifies a progress point. The ID is written as the BPF attach
// cookie and is stable within one experiment run.
type ProbePoint struct {
	ID    uint32
	Probe tracer.ProbeSpec
	Name  string
}

// TargetPoint identifies a region whose virtual speedup is evaluated.
type TargetPoint struct {
	ID         uint32
	EnterProbe tracer.ProbeSpec
	ExitProbe  tracer.ProbeSpec
	Name       string
}

// OverheadBudget describes soft validation limits recorded in the final report.
type OverheadBudget struct {
	MaxObservationOverhead float64
	MaxContextSwitchRatio  float64
}

// Normalize fills defaults without weakening validation.
func (c *Config) Normalize() {
	if len(c.Speedups) == 0 {
		c.Speedups = []int{0, 5, 10, 20}
	}
	if c.WindowDuration == 0 {
		c.WindowDuration = defaultWindowDuration
	}
	if c.Cooldown == 0 {
		c.Cooldown = defaultCooldown
	}
	if c.MaxThreads == 0 {
		c.MaxThreads = defaultMaxThreads
	}
	if c.ReportPath == "" {
		c.ReportPath = defaultReportPath
	}
}

// Validate checks the experiment contract before any process is perturbed.
func (c Config) Validate() error {
	if c.PID <= 0 {
		return errMissingPID
	}
	if len(c.ProgressPoints) == 0 {
		return errMissingProgress
	}
	if len(c.Targets) == 0 {
		return errMissingTarget
	}
	if len(c.Targets) > 1 {
		return errors.New("the experimental MVP supports exactly one target")
	}
	if c.WindowDuration <= 0 {
		return fmt.Errorf("window duration must be positive: %s", c.WindowDuration)
	}
	if c.Cooldown < 0 {
		return fmt.Errorf("cooldown must not be negative: %s", c.Cooldown)
	}
	if c.MaxThreads <= 0 {
		return fmt.Errorf("max threads must be positive: %d", c.MaxThreads)
	}
	if c.ReportPath == "" {
		return errors.New("report path must not be empty")
	}
	seenPointIDs := make(map[uint32]struct{}, len(c.ProgressPoints))
	for _, p := range c.ProgressPoints {
		if p.ID == 0 {
			return errors.New("progress point id must be non-zero")
		}
		if _, exists := seenPointIDs[p.ID]; exists {
			return fmt.Errorf("duplicate progress point id %d", p.ID)
		}
		seenPointIDs[p.ID] = struct{}{}
		if p.Probe.Type != tracer.ProbeTypeUprobe {
			return fmt.Errorf("progress point %d must use uprobe", p.ID)
		}
	}
	seenTargetIDs := make(map[uint32]struct{}, len(c.Targets))
	for _, target := range c.Targets {
		if target.ID == 0 {
			return errors.New("target id must be non-zero")
		}
		if _, exists := seenTargetIDs[target.ID]; exists {
			return fmt.Errorf("duplicate target id %d", target.ID)
		}
		seenTargetIDs[target.ID] = struct{}{}
		if target.EnterProbe.Type != tracer.ProbeTypeUprobe {
			return fmt.Errorf("target %d enter probe must use uprobe", target.ID)
		}
		if target.ExitProbe.Type != tracer.ProbeTypeUretprobe {
			return fmt.Errorf("target %d exit probe must use uretprobe", target.ID)
		}
	}
	for _, speedup := range c.Speedups {
		if speedup < 0 || speedup > 100 {
			return fmt.Errorf("speedup must be in [0, 100]: %d", speedup)
		}
	}
	return nil
}

// Phase is the causal experiment state.
type Phase uint8

const (
	PhaseIdle Phase = iota
	PhaseBaseline
	PhaseSpeedup
	PhaseCooldown
	PhaseError
)

func (p Phase) String() string {
	switch p {
	case PhaseIdle:
		return "idle"
	case PhaseBaseline:
		return "baseline"
	case PhaseSpeedup:
		return "speedup"
	case PhaseCooldown:
		return "cooldown"
	case PhaseError:
		return "error"
	default:
		return "unknown"
	}
}

// Window defines a single baseline or perturbation interval.
type Window struct {
	Phase        Phase
	Speedup      int
	StartedAt    time.Time
	EndsAt       time.Time
	ExperimentID uint64
}
