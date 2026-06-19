// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0
//go:build linux

package coz

import (
	"math/rand/v2"
)

// Cell is one (target, speedup) experiment unit. Every window scheduled by the
// rotation is one repetition of one cell, identified to the BPF program by
// CellID (which is what coz.ebpf.c stores as experiment_id).
type Cell struct {
	ID        uint32
	TargetIdx int
	Speedup   int
}

// BuildCells builds the cartesian product Targets × Speedups. CellID encoding:
//
//	cell_id = target_idx * len(speedups) + speedup_idx + 1
//
// The +1 guarantees cell_id > 0 — the BPF program treats experiment_id == 0
// as "off". The encoding is also reversible so consumers can decode cells from
// the raw report if needed.
func BuildCells(targets []TargetPoint, speedups []int) []Cell {
	cells := make([]Cell, 0, len(targets)*len(speedups))
	for ti := range targets {
		for si, speedup := range speedups {
			cells = append(cells, Cell{
				ID:        uint32(ti*len(speedups)+si) + 1,
				TargetIdx: ti,
				Speedup:   speedup,
			})
		}
	}
	return cells
}

// Schedule generates the per-round execution order using block-randomization:
// the full cell pool is independently shuffled at the start of each round.
// Any time-correlated drift (GC, autoscaler, thermal) becomes orthogonal to the
// (target, speedup) axes so per-cell aggregates are not biased by run-time
// drift.
type Schedule struct {
	cells []Cell
	rng   *rand.Rand
}

func NewSchedule(cells []Cell, seed uint64) *Schedule {
	src := rand.NewPCG(seed, seed^0x9E3779B97F4A7C15)
	return &Schedule{
		cells: cells,
		rng:   rand.New(src),
	}
}

// Round returns one shuffled traversal of the cell pool.
func (s *Schedule) Round() []Cell {
	out := make([]Cell, len(s.cells))
	copy(out, s.cells)
	s.rng.Shuffle(len(out), func(i, j int) { out[i], out[j] = out[j], out[i] })
	return out
}

// PhaseForSpeedup classifies a cell for reporting.
func PhaseForSpeedup(speedup int) Phase {
	if speedup == 0 {
		return PhaseBaseline
	}
	return PhaseSpeedup
}
