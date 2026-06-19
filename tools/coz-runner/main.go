// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

//go:build linux

package main

import (
	"context"
	"flag"
	"fmt"
	"os"
	"runtime"
	"strconv"
	"strings"
	"time"

	"go.opentelemetry.io/ebpf-profiler/internal/experimental/coz"
	"go.opentelemetry.io/ebpf-profiler/tracer"
)

type stringList []string

func (s *stringList) String() string { return strings.Join(*s, ",") }
func (s *stringList) Set(value string) error {
	*s = append(*s, value)
	return nil
}

func main() {
	os.Exit(run())
}

func run() int {
	var (
		pid           int
		target        string
		progress      stringList
		speedupsArg   string
		window        time.Duration
		cooldown      time.Duration
		maxThreads    int
		reportPath    string
		bpfObject     string
		ptraceQuantum time.Duration
	)
	flag.IntVar(&pid, "pid", 0, "Target process PID.")
	flag.Var(&progress, "progress", "Progress point probe, repeatable: uprobe:/path/to/bin:symbol.")
	flag.StringVar(&target, "target", "", "Target function probe: uprobe:/path/to/bin:symbol.")
	flag.StringVar(&speedupsArg, "speedups", "0,5,10,20,100", "Comma-separated virtual speedups in percent (100 = full pause of non-target TIDs during the window).")
	flag.DurationVar(&window, "window", 10*time.Second, "Experiment window duration.")
	flag.DurationVar(&cooldown, "cooldown", time.Second, "Cooldown duration between windows.")
	flag.IntVar(&maxThreads, "max-threads", 256, "Maximum TIDs to attach with ptrace.")
	flag.StringVar(&reportPath, "report", "coz-report.json", "JSON report output path.")
	flag.StringVar(&bpfObject, "bpf-object", fmt.Sprintf("support/ebpf/coz.ebpf.%s", runtime.GOARCH), "Path to standalone Coz eBPF object.")
	flag.DurationVar(&ptraceQuantum, "ptrace-quantum", 10*time.Millisecond, "Base ptrace perturbation quantum.")
	flag.Parse()

	cfg, err := buildConfig(pid, progress, target, speedupsArg, window, cooldown, maxThreads, reportPath)
	if err != nil {
		fmt.Fprintf(os.Stderr, "invalid config: %v\n", err)
		return 2
	}
	ctx := context.Background()
	programs, err := coz.LoadProgramSet(ctx, bpfObject)
	if err != nil {
		fmt.Fprintf(os.Stderr, "failed to load Coz eBPF object: %v\n", err)
		return 1
	}
	controller, err := coz.NewController(cfg, programs, coz.NewPtraceBackend(ptraceQuantum), nil)
	if err != nil {
		fmt.Fprintf(os.Stderr, "failed to create controller: %v\n", err)
		return 1
	}
	defer controller.Close()

	report, err := controller.RunExperiment(ctx)
	if err != nil {
		fmt.Fprintf(os.Stderr, "experiment failed: %v\n", err)
		return 1
	}
	fmt.Printf("Wrote Coz-like report to %s (%d windows)\n", cfg.ReportPath, len(report.Windows))
	return 0
}

func buildConfig(pid int, progressSpecs []string, targetSpec string, speedupsArg string,
	window time.Duration, cooldown time.Duration, maxThreads int, reportPath string,
) (coz.Config, error) {
	speedups, err := parseSpeedups(speedupsArg)
	if err != nil {
		return coz.Config{}, err
	}
	progressPoints := make([]coz.ProbePoint, 0, len(progressSpecs))
	for idx, spec := range progressSpecs {
		probe, err := parseUprobe(spec)
		if err != nil {
			return coz.Config{}, fmt.Errorf("progress %q: %w", spec, err)
		}
		progressPoints = append(progressPoints, coz.ProbePoint{
			ID:    uint32(idx + 1),
			Probe: *probe,
			Name:  probe.Symbol,
		})
	}
	targetProbe, err := parseUprobe(targetSpec)
	if err != nil {
		return coz.Config{}, fmt.Errorf("target %q: %w", targetSpec, err)
	}
	exitProbe := *targetProbe
	exitProbe.Type = tracer.ProbeTypeUretprobe

	cfg := coz.Config{
		PID:            pid,
		ProgressPoints: progressPoints,
		Targets: []coz.TargetPoint{{
			ID:         1,
			EnterProbe: *targetProbe,
			ExitProbe:  exitProbe,
			Name:       targetProbe.Symbol,
		}},
		Speedups:       speedups,
		WindowDuration: window,
		Cooldown:       cooldown,
		MaxThreads:     maxThreads,
		ReportPath:     reportPath,
	}
	cfg.Normalize()
	return cfg, cfg.Validate()
}

func parseUprobe(spec string) (*tracer.ProbeSpec, error) {
	probe, err := tracer.ParseProbe(spec)
	if err != nil {
		return nil, err
	}
	if probe.Type != tracer.ProbeTypeUprobe {
		return nil, fmt.Errorf("expected uprobe, got %s", probe.Type)
	}
	return probe, nil
}

func parseSpeedups(input string) ([]int, error) {
	parts := strings.Split(input, ",")
	out := make([]int, 0, len(parts))
	for _, part := range parts {
		part = strings.TrimSpace(part)
		if part == "" {
			continue
		}
		speedup, err := strconv.Atoi(part)
		if err != nil {
			return nil, fmt.Errorf("parse speedup %q: %w", part, err)
		}
		out = append(out, speedup)
	}
	if len(out) == 0 {
		return nil, fmt.Errorf("at least one speedup is required")
	}
	return out, nil
}
