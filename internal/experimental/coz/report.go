// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0
//go:build linux

package coz

import (
	"encoding/json"
	"fmt"
	"math"
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
	TargetIdx    int                `json:"target_idx"`
	TargetID     uint32             `json:"target_id"`
	TargetName   string             `json:"target_name"`
	Progress     map[uint32]uint64  `json:"progress"`
	Throughput   map[uint32]float64 `json:"throughput_per_second"`
	Perturbation PerturbationStats  `json:"perturbation"`
	Overhead     OverheadStats      `json:"overhead"`
	Errors       []string           `json:"errors,omitempty"`
}

// CellSummary aggregates all repetitions of one (target, speedup) cell for one
// progress point.
type CellSummary struct {
	TargetID            uint32  `json:"target_id"`
	TargetName          string  `json:"target_name"`
	Speedup             int     `json:"speedup"`
	PointID             uint32  `json:"point_id"`
	Reps                int     `json:"reps"`
	ThroughputMean      float64 `json:"throughput_mean"`
	ThroughputStdDev    float64 `json:"throughput_stddev"`
	BaselineDeltaMean   float64 `json:"baseline_delta_mean"`
	BaselineDeltaStdDev float64 `json:"baseline_delta_stddev"`
}

// TargetRanking is filled by Phase 4 (analysis) — declared here so the JSON
// shape is stable across phases. Phase 1–2 emit empty values; Phase 4 populates
// slope, CI, status.
type TargetRanking struct {
	TargetID         uint32  `json:"target_id"`
	TargetName       string  `json:"target_name"`
	PointID          uint32  `json:"point_id"`
	Slope            float64 `json:"slope"`
	SlopeCILow       float64 `json:"slope_ci_low"`
	SlopeCIHigh      float64 `json:"slope_ci_high"`
	SampleCount      int     `json:"sample_count"`
	BaselineMedian   float64 `json:"baseline_median"`
	Status           string  `json:"status"`
	StatusDetail     string  `json:"status_detail,omitempty"`
	PredictedGain20  float64 `json:"predicted_gain_at_20_pct"`
	PredictedGain100 float64 `json:"predicted_gain_at_100_pct"`
}

// Report is the JSON artifact produced by the experimental controller.
type Report struct {
	PID            int             `json:"pid"`
	StartedAt      time.Time       `json:"started_at"`
	Duration       time.Duration   `json:"duration_ns"`
	RotationSeed   uint64          `json:"rotation_seed"`
	RoundsRun      int             `json:"rounds_run"`
	ProgressPoints []PointReport   `json:"progress_points"`
	Targets        []TargetReport  `json:"targets"`
	Windows        []WindowResult  `json:"windows"`
	Cells          []CellSummary   `json:"cells"`
	TargetsRanked  []TargetRanking `json:"targets_ranked"`
}

func newReport(cfg Config, rotationSeed uint64, roundsRun int, startedAt time.Time, windows []WindowResult) *Report {
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
	cells := aggregateCells(windows)
	return &Report{
		PID:            cfg.PID,
		StartedAt:      startedAt,
		Duration:       time.Since(startedAt),
		RotationSeed:   rotationSeed,
		RoundsRun:      roundsRun,
		ProgressPoints: points,
		Targets:        targets,
		Windows:        windows,
		Cells:          cells,
		TargetsRanked:  nil,
	}
}

type cellKey struct {
	targetID uint32
	speedup  int
	pointID  uint32
}

// aggregateCells rolls window-level throughput up to per-(target, speedup,
// point) summaries with mean and sample stddev. Per-cell variance is what the
// slope analysis (Phase 4) consumes.
func aggregateCells(windows []WindowResult) []CellSummary {
	if len(windows) == 0 {
		return nil
	}
	groups := make(map[cellKey][]float64)
	names := make(map[uint32]string)
	for _, w := range windows {
		names[w.TargetID] = w.TargetName
		for pointID, tput := range w.Throughput {
			k := cellKey{targetID: w.TargetID, speedup: w.Speedup, pointID: pointID}
			groups[k] = append(groups[k], tput)
		}
	}
	// Compute the baseline mean per (target, point) so each non-baseline cell
	// can report its delta vs baseline. The slope analysis later uses the
	// same convention.
	baselineMean := make(map[cellKey]float64)
	for k, vals := range groups {
		if k.speedup != 0 {
			continue
		}
		baselineMean[cellKey{targetID: k.targetID, pointID: k.pointID}] = mean(vals)
	}
	out := make([]CellSummary, 0, len(groups))
	for k, vals := range groups {
		m := mean(vals)
		base := baselineMean[cellKey{targetID: k.targetID, pointID: k.pointID}]
		var deltaVals []float64
		if base > 0 {
			deltaVals = make([]float64, len(vals))
			for i, v := range vals {
				deltaVals[i] = (v - base) / base
			}
		}
		out = append(out, CellSummary{
			TargetID:            k.targetID,
			TargetName:          names[k.targetID],
			Speedup:             k.speedup,
			PointID:             k.pointID,
			Reps:                len(vals),
			ThroughputMean:      m,
			ThroughputStdDev:    stddev(vals, m),
			BaselineDeltaMean:   mean(deltaVals),
			BaselineDeltaStdDev: stddev(deltaVals, mean(deltaVals)),
		})
	}
	return out
}

func mean(xs []float64) float64 {
	if len(xs) == 0 {
		return 0
	}
	var s float64
	for _, x := range xs {
		s += x
	}
	return s / float64(len(xs))
}

func stddev(xs []float64, m float64) float64 {
	if len(xs) < 2 {
		return 0
	}
	var s float64
	for _, x := range xs {
		d := x - m
		s += d * d
	}
	return math.Sqrt(s / float64(len(xs)-1))
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
