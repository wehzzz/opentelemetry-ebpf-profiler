// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0
//go:build linux

package coz

import (
	"context"
	"errors"
	"fmt"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/link"

	"go.opentelemetry.io/ebpf-profiler/tracer"
)

const (
	mapCozProgressCounts   = "coz_progress_counts"
	mapCozTargetState      = "coz_target_state"
	mapCozActiveExperiment = "coz_active_experiment"

	progCozProgress    = "coz_progress"
	progCozTargetEnter = "coz_target_enter"
	progCozTargetExit  = "coz_target_exit"
)

// ProgramSet adapts loaded eBPF programs and maps to the controller interface.
type ProgramSet struct {
	programs map[string]*ebpf.Program
	maps     map[string]*ebpf.Map
	links    []link.Link
}

func NewProgramSet(programs map[string]*ebpf.Program, maps map[string]*ebpf.Map) *ProgramSet {
	return &ProgramSet{
		programs: programs,
		maps:     maps,
	}
}

func (p *ProgramSet) Attach(_ context.Context, cfg Config) error {
	for _, point := range cfg.ProgressPoints {
		lnk, err := p.attachUprobe(point.Probe, progCozProgress, uint64(point.ID), cfg.PID)
		if err != nil {
			_ = p.Close()
			return fmt.Errorf("attach progress point %d: %w", point.ID, err)
		}
		p.links = append(p.links, lnk)
	}
	for _, target := range cfg.Targets {
		enter, err := p.attachUprobe(target.EnterProbe, progCozTargetEnter, uint64(target.ID), cfg.PID)
		if err != nil {
			_ = p.Close()
			return fmt.Errorf("attach target %d enter probe: %w", target.ID, err)
		}
		p.links = append(p.links, enter)

		exit, err := p.attachUprobe(target.ExitProbe, progCozTargetExit, uint64(target.ID), cfg.PID)
		if err != nil {
			_ = p.Close()
			return fmt.Errorf("attach target %d exit probe: %w", target.ID, err)
		}
		p.links = append(p.links, exit)
	}
	return nil
}

func (p *ProgramSet) SetActiveExperiment(_ context.Context, experimentID uint32) error {
	m, ok := p.maps[mapCozActiveExperiment]
	if !ok {
		return fmt.Errorf("map %s is not available", mapCozActiveExperiment)
	}
	key := uint32(0)
	return m.Update(&key, &experimentID, ebpf.UpdateAny)
}

func (p *ProgramSet) SnapshotProgress(context.Context) (map[CounterKey]uint64, error) {
	m, ok := p.maps[mapCozProgressCounts]
	if !ok {
		return nil, fmt.Errorf("map %s is not available", mapCozProgressCounts)
	}
	out := make(map[CounterKey]uint64)
	var key CounterKey
	var values []CounterValue
	it := m.Iterate()
	for it.Next(&key, &values) {
		var sum uint64
		for _, value := range values {
			sum += value.Count
		}
		out[key] = sum
	}
	if err := it.Err(); err != nil {
		return nil, fmt.Errorf("iterate progress counters: %w", err)
	}
	return out, nil
}

func (p *ProgramSet) SnapshotTargets(context.Context) (map[uint64]ThreadState, error) {
	m, ok := p.maps[mapCozTargetState]
	if !ok {
		return nil, fmt.Errorf("map %s is not available", mapCozTargetState)
	}
	out := make(map[uint64]ThreadState)
	var key uint64
	var value ThreadState
	it := m.Iterate()
	for it.Next(&key, &value) {
		out[key] = value
	}
	if err := it.Err(); err != nil {
		return nil, fmt.Errorf("iterate target state: %w", err)
	}
	return out, nil
}

func (p *ProgramSet) Close() error {
	var err error
	for _, lnk := range p.links {
		if closeErr := lnk.Close(); closeErr != nil {
			err = errors.Join(err, fmt.Errorf("close coz link: %w", closeErr))
		}
	}
	p.links = nil
	return err
}

func (p *ProgramSet) attachUprobe(spec tracer.ProbeSpec, programName string, cookie uint64, pid int) (link.Link, error) {
	prog, ok := p.programs[programName]
	if !ok {
		return nil, fmt.Errorf("program %s is not available", programName)
	}
	ex, err := link.OpenExecutable(spec.Target)
	if err != nil {
		return nil, err
	}
	opts := &link.UprobeOptions{
		PID:    pid,
		Cookie: cookie,
	}
	switch spec.Type {
	case tracer.ProbeTypeUprobe:
		return ex.Uprobe(spec.Symbol, prog, opts)
	case tracer.ProbeTypeUretprobe:
		return ex.Uretprobe(spec.Symbol, prog, opts)
	default:
		return nil, fmt.Errorf("unsupported coz probe type %s", spec.Type)
	}
}
