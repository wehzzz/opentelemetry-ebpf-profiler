// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0
//go:build linux

package coz

import (
	"encoding/json"
	"fmt"
	"os"
	"time"
)

// PointReport describes a configured progress point in the emitted report.
type PointReport struct {
	ID     uint32 `json:"id"`
	Name   string `json:"name"`
	Target string `json:"target"`
	Symbol string `json:"symbol"`
}

// TargetReport describes a configured target region in the emitted report.
type TargetReport struct {
	ID          uint32 `json:"id"`
	Name        string `json:"name"`
	EnterTarget string `json:"enter_target"`
	EnterSymbol string `json:"enter_symbol"`
	ExitTarget  string `json:"exit_target"`
	ExitSymbol  string `json:"exit_symbol"`
}

// PerturbationStats records ptrace controller activity for one window.
type PerturbationStats struct {
	Attempts       uint64        `json:"attempts"`
	Failures       uint64        `json:"failures"`
	DelayedThreads uint64        `json:"delayed_threads"`
	DelayedTime    time.Duration `json:"delayed_time_ns"`
	Invalidated    bool          `json:"invalidated"`
}

// OverheadStats records local controller overhead for one window.
type OverheadStats struct {
	SnapshotDuration time.Duration `json:"snapshot_duration_ns"`
	ApplyDuration    time.Duration `json:"apply_duration_ns"`
}

// WindowResult contains raw data for one experiment window.
type WindowResult struct {
	ExperimentID uint64             `json:"experiment_id"`
	Phase        string             `json:"phase"`
	Speedup      int                `json:"speedup"`
	StartedAt    time.Time          `json:"started_at"`
	Duration     time.Duration      `json:"duration_ns"`
	Progress     map[uint32]uint64  `json:"progress"`
	Throughput   map[uint32]float64 `json:"throughput_per_second"`
	Perturbation PerturbationStats  `json:"perturbation"`
	Overhead     OverheadStats      `json:"overhead"`
	Errors       []string           `json:"errors,omitempty"`
}

// Report is the JSON artifact produced by the experimental controller.
type Report struct {
	PID            int            `json:"pid"`
	StartedAt      time.Time      `json:"started_at"`
	Duration       time.Duration  `json:"duration_ns"`
	ProgressPoints []PointReport  `json:"progress_points"`
	Targets        []TargetReport `json:"targets"`
	Windows        []WindowResult `json:"windows"`
}

func newReport(cfg Config, startedAt time.Time, windows []WindowResult) *Report {
	points := make([]PointReport, 0, len(cfg.ProgressPoints))
	for _, point := range cfg.ProgressPoints {
		points = append(points, PointReport{
			ID:     point.ID,
			Name:   point.Name,
			Target: point.Probe.Target,
			Symbol: point.Probe.Symbol,
		})
	}
	targets := make([]TargetReport, 0, len(cfg.Targets))
	for _, target := range cfg.Targets {
		targets = append(targets, TargetReport{
			ID:          target.ID,
			Name:        target.Name,
			EnterTarget: target.EnterProbe.Target,
			EnterSymbol: target.EnterProbe.Symbol,
			ExitTarget:  target.ExitProbe.Target,
			ExitSymbol:  target.ExitProbe.Symbol,
		})
	}
	return &Report{
		PID:            cfg.PID,
		StartedAt:      startedAt,
		Duration:       time.Since(startedAt),
		ProgressPoints: points,
		Targets:        targets,
		Windows:        windows,
	}
}

// WriteReport writes a pretty-printed JSON report to path.
func WriteReport(path string, report *Report) error {
	file, err := os.Create(path)
	if err != nil {
		return fmt.Errorf("create report %q: %w", path, err)
	}
	defer file.Close()

	enc := json.NewEncoder(file)
	enc.SetIndent("", "  ")
	if err := enc.Encode(report); err != nil {
		return fmt.Errorf("encode report %q: %w", path, err)
	}
	return nil
}
