// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0
//go:build linux

package coz

import (
	"context"
	"fmt"
	"time"
)

// CounterKey mirrors the eBPF progress counter key.
type CounterKey struct {
	ExperimentID uint32
	PointID      uint32
}

// CounterValue mirrors one per-CPU progress counter value.
type CounterValue struct {
	Count uint64
}

// ThreadState mirrors the eBPF target state value.
type ThreadState struct {
	TargetID    uint32
	Depth       uint32
	EnteredAtNS uint64
}

// BPFProgramSet is the narrow interface the controller needs from eBPF.
type BPFProgramSet interface {
	Attach(ctx context.Context, cfg Config) error
	SetActiveExperiment(ctx context.Context, experimentID uint32) error
	SnapshotProgress(ctx context.Context) (map[CounterKey]uint64, error)
	SnapshotTargets(ctx context.Context) (map[uint64]ThreadState, error)
	Close() error
}

// DeltaCounter computes monotonically increasing deltas from snapshot maps.
type DeltaCounter struct {
	previous map[CounterKey]uint64
}

func NewDeltaCounter() *DeltaCounter {
	return &DeltaCounter{previous: make(map[CounterKey]uint64)}
}

func (d *DeltaCounter) Delta(snapshot map[CounterKey]uint64, experimentID uint32) map[uint32]uint64 {
	out := make(map[uint32]uint64)
	for key, value := range snapshot {
		if key.ExperimentID != experimentID {
			continue
		}
		prev := d.previous[key]
		if value >= prev {
			out[key.PointID] += value - prev
		}
		d.previous[key] = value
	}
	return out
}

func throughput(progress map[uint32]uint64, duration time.Duration) map[uint32]float64 {
	out := make(map[uint32]float64, len(progress))
	if duration <= 0 {
		return out
	}
	seconds := duration.Seconds()
	for pointID, count := range progress {
		out[pointID] = float64(count) / seconds
	}
	return out
}

// targetStateForTarget keeps only TIDs currently inside the requested target.
// Threads inside *other* targets are not considered "active" for the
// perturbation backend's decisions in this window — their work is irrelevant
// to the currently-measured cell.
func targetStateForTarget(states map[uint64]ThreadState, targetID uint32) TargetState {
	target := TargetState{
		ActiveTIDs: make(map[int]ThreadState, len(states)),
	}
	for pidTID, state := range states {
		if state.Depth == 0 || state.TargetID != targetID {
			continue
		}
		tid := int(uint32(pidTID))
		target.ActiveTIDs[tid] = state
	}
	return target
}

type noopBPF struct{}

func (noopBPF) Attach(context.Context, Config) error              { return nil }
func (noopBPF) SetActiveExperiment(context.Context, uint32) error { return nil }
func (noopBPF) SnapshotProgress(context.Context) (map[CounterKey]uint64, error) {
	return nil, fmt.Errorf("coz bpf program set is not configured")
}
func (noopBPF) SnapshotTargets(context.Context) (map[uint64]ThreadState, error) {
	return nil, fmt.Errorf("coz bpf program set is not configured")
}
func (noopBPF) Close() error { return nil }
