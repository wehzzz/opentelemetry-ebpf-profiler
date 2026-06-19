// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package coz

import (
	"context"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"go.opentelemetry.io/ebpf-profiler/tracer"
)

type fakeBPF struct {
	progressSnapshots []map[CounterKey]uint64
	targets           map[uint64]ThreadState
	active            []uint32
	closed            bool
}

func (f *fakeBPF) Attach(context.Context, Config) error { return nil }

func (f *fakeBPF) SetActiveExperiment(_ context.Context, experimentID uint32) error {
	f.active = append(f.active, experimentID)
	return nil
}

func (f *fakeBPF) SnapshotProgress(context.Context) (map[CounterKey]uint64, error) {
	if len(f.progressSnapshots) == 0 {
		return map[CounterKey]uint64{}, nil
	}
	snapshot := f.progressSnapshots[0]
	f.progressSnapshots = f.progressSnapshots[1:]
	return snapshot, nil
}

func (f *fakeBPF) SnapshotTargets(context.Context) (map[uint64]ThreadState, error) {
	return f.targets, nil
}

func (f *fakeBPF) Close() error {
	f.closed = true
	return nil
}

type fakePerturbation struct {
	attached    []int
	applied     []int
	targetCalls int
	detached    bool
}

func (f *fakePerturbation) Attach(tids []int) error {
	f.attached = append(f.attached, tids...)
	return nil
}

func (f *fakePerturbation) Apply(ctx context.Context, target func(context.Context) (TargetState, error), speedup int, duration time.Duration) (PerturbationStats, error) {
	if _, err := target(ctx); err != nil {
		return PerturbationStats{Invalidated: true}, err
	}
	f.targetCalls++
	f.applied = append(f.applied, speedup)
	return PerturbationStats{}, sleepContext(ctx, duration)
}

func (f *fakePerturbation) Detach() error {
	f.detached = true
	return nil
}

type failingTIDs struct{}

func (failingTIDs) TIDs(int, int) ([]int, error) {
	return nil, os.ErrNotExist
}

type fakeTIDs []int

func (f fakeTIDs) TIDs(int, int) ([]int, error) { return []int(f), nil }

func testConfig(t *testing.T) Config {
	t.Helper()
	return Config{
		PID: 1234,
		ProgressPoints: []ProbePoint{{
			ID: 1,
			Probe: tracer.ProbeSpec{
				Type:   tracer.ProbeTypeUprobe,
				Target: "/bin/test",
				Symbol: "done",
			},
			Name: "done",
		}},
		Targets: []TargetPoint{{
			ID: 7,
			EnterProbe: tracer.ProbeSpec{
				Type:   tracer.ProbeTypeUprobe,
				Target: "/bin/test",
				Symbol: "hot",
			},
			ExitProbe: tracer.ProbeSpec{
				Type:   tracer.ProbeTypeUretprobe,
				Target: "/bin/test",
				Symbol: "hot",
			},
			Name: "hot",
		}},
		Speedups:       []int{0},
		WindowDuration: time.Millisecond,
		Cooldown:       0,
		MaxThreads:     8,
		ReportPath:     filepath.Join(t.TempDir(), "report.json"),
	}
}

func TestConfigValidate(t *testing.T) {
	cfg := testConfig(t)
	require.NoError(t, cfg.Validate())

	cfg.ProgressPoints[0].ID = 0
	require.ErrorContains(t, cfg.Validate(), "progress point id")
}

func TestConfigValidateRejectsMultipleTargets(t *testing.T) {
	cfg := testConfig(t)
	cfg.Targets = append(cfg.Targets, cfg.Targets[0])
	cfg.Targets[1].ID = 8

	require.ErrorContains(t, cfg.Validate(), "exactly one target")
}

func TestControllerRunExperimentWritesReport(t *testing.T) {
	cfg := testConfig(t)
	bpf := &fakeBPF{
		progressSnapshots: []map[CounterKey]uint64{
			{},
			{{ExperimentID: 1, PointID: 1}: 42},
		},
		targets: map[uint64]ThreadState{},
	}
	ptracer := &fakePerturbation{}
	controller, err := NewController(cfg, bpf, ptracer, fakeTIDs{1234, 1235})
	require.NoError(t, err)
	defer controller.Close()

	report, err := controller.RunExperiment(context.Background())
	require.NoError(t, err)
	require.Len(t, report.Windows, 1)
	require.Equal(t, uint64(42), report.Windows[0].Progress[1])
	require.Equal(t, []uint32{1}, bpf.active)
	require.Equal(t, []int{1234, 1235}, ptracer.attached)
	require.Equal(t, []int{0}, ptracer.applied)
	require.Equal(t, 1, ptracer.targetCalls)

	data, err := os.ReadFile(cfg.ReportPath)
	require.NoError(t, err)
	require.Contains(t, string(data), `"progress"`)
}

func TestStartRollsBackWhenTIDEnumerationFails(t *testing.T) {
	cfg := testConfig(t)
	bpf := &fakeBPF{}
	ptracer := &fakePerturbation{}
	controller, err := NewController(cfg, bpf, ptracer, failingTIDs{})
	require.NoError(t, err)

	err = controller.Start(context.Background())
	require.Error(t, err)
	require.True(t, bpf.closed)
	require.True(t, ptracer.detached)
}

func TestDeltaCounterIgnoresOtherExperiments(t *testing.T) {
	counter := NewDeltaCounter()
	delta := counter.Delta(map[CounterKey]uint64{
		{ExperimentID: 1, PointID: 1}: 10,
		{ExperimentID: 2, PointID: 1}: 50,
	}, 1)
	require.Equal(t, map[uint32]uint64{1: 10}, delta)

	delta = counter.Delta(map[CounterKey]uint64{
		{ExperimentID: 1, PointID: 1}: 15,
		{ExperimentID: 2, PointID: 1}: 55,
	}, 1)
	require.Equal(t, map[uint32]uint64{1: 5}, delta)
}
