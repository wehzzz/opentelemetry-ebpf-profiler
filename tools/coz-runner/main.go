// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

//go:build linux

package main

import (
	"context"
	"flag"
	"fmt"
	"os"
	"regexp"
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
		pid             int
		targets         stringList
		progress        stringList
		speedupsArg     string
		window          time.Duration
		cooldown        time.Duration
		rounds          int
		budget          time.Duration
		rotationSeed    uint64
		maxThreads      int
		reportPath      string
		bpfObject       string
		ptraceQuantum   time.Duration
		autoTargets     int
		autoDuration    time.Duration
		autoFreqHz      uint64
		autoFilterRegex string
	)
	flag.IntVar(&pid, "pid", 0, "Target process PID.")
	flag.Var(&progress, "progress", "Progress point probe, repeatable: uprobe:/path/to/bin:symbol.")
	flag.Var(&targets, "target", "Target function probe, repeatable. When unset, -auto-targets picks them.")
	flag.StringVar(&speedupsArg, "speedups", "0,5,10,20,100", "Comma-separated virtual speedups in percent (100 = full pause of non-target TIDs during the window).")
	flag.DurationVar(&window, "window", 500*time.Millisecond, "Per-window duration.")
	flag.DurationVar(&cooldown, "cooldown", 100*time.Millisecond, "Cooldown after a target swap (not applied between same-target windows).")
	flag.IntVar(&rounds, "rounds", 5, "Number of block-randomized rotation rounds. 0 = unlimited (use -budget).")
	flag.DurationVar(&budget, "budget", 0, "Wall-clock budget for the whole run. 0 = unlimited (use -rounds).")
	flag.Uint64Var(&rotationSeed, "rotation-seed", 0, "Seed for cell shuffling. 0 = time-based, written to report for reproducibility.")
	flag.IntVar(&maxThreads, "max-threads", 256, "Maximum TIDs to attach with ptrace.")
	flag.StringVar(&reportPath, "report", "coz-report.json", "JSON report output path.")
	flag.StringVar(&bpfObject, "bpf-object", fmt.Sprintf("support/ebpf/coz.ebpf.%s", runtime.GOARCH), "Path to standalone Coz eBPF object.")
	flag.DurationVar(&ptraceQuantum, "ptrace-quantum", 10*time.Millisecond, "Base ptrace perturbation quantum.")
	flag.IntVar(&autoTargets, "auto-targets", 5, "When -target is unset, auto-pick this many hot functions via PC sampling. 0 = disable auto-pick (requires -target).")
	flag.DurationVar(&autoDuration, "auto-duration", 2*time.Second, "Calibration window for auto-pick PC sampling.")
	flag.Uint64Var(&autoFreqHz, "auto-freq-hz", 999, "Sampling frequency for auto-pick.")
	flag.StringVar(&autoFilterRegex, "auto-filter", "", "Regex matching symbol names to exclude from auto-pick. Empty uses the built-in noise filter (libc/pthread internals).")
	flag.Parse()

	ctx := context.Background()
	if len(targets) == 0 && autoTargets > 0 {
		picked, err := pickTargetsFromSamples(ctx, pid, autoDuration, autoFreqHz, autoTargets, autoFilterRegex)
		if err != nil {
			fmt.Fprintf(os.Stderr, "auto-pick failed: %v\n", err)
			return 1
		}
		for _, hit := range picked {
			targets = append(targets, fmt.Sprintf("uprobe:%s:%s", hit.BinaryPath, hit.Symbol))
			fmt.Fprintf(os.Stderr, "auto-pick target: %s (%s, %d samples)\n", hit.Symbol, hit.BinaryPath, hit.Count)
		}
	}

	cfg, err := buildConfig(pid, progress, targets, speedupsArg, window, cooldown,
		rounds, budget, rotationSeed, maxThreads, reportPath)
	if err != nil {
		fmt.Fprintf(os.Stderr, "invalid config: %v\n", err)
		return 2
	}
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
	fmt.Printf("Wrote Coz-like report to %s (%d windows, %d rounds, seed %d)\n",
		cfg.ReportPath, len(report.Windows), report.RoundsRun, report.RotationSeed)
	return 0
}

func buildConfig(pid int, progressSpecs, targetSpecs []string, speedupsArg string,
	window, cooldown time.Duration, rounds int, budget time.Duration, rotationSeed uint64,
	maxThreads int, reportPath string,
) (coz.Config, error) {
	speedups, err := parseSpeedups(speedupsArg)
	if err != nil {
		return coz.Config{}, err
	}
	if len(targetSpecs) == 0 {
		return coz.Config{}, fmt.Errorf("at least one -target probe is required (auto-pick lands in a follow-up)")
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
	targetPoints := make([]coz.TargetPoint, 0, len(targetSpecs))
	for idx, spec := range targetSpecs {
		probe, err := parseUprobe(spec)
		if err != nil {
			return coz.Config{}, fmt.Errorf("target %q: %w", spec, err)
		}
		exitProbe := *probe
		exitProbe.Type = tracer.ProbeTypeUretprobe
		targetPoints = append(targetPoints, coz.TargetPoint{
			ID:         uint32(idx + 1),
			EnterProbe: *probe,
			ExitProbe:  exitProbe,
			Name:       probe.Symbol,
		})
	}

	cfg := coz.Config{
		PID:            pid,
		ProgressPoints: progressPoints,
		Targets:        targetPoints,
		Speedups:       speedups,
		WindowDuration: window,
		Cooldown:       cooldown,
		Rounds:         rounds,
		Budget:         budget,
		RotationSeed:   rotationSeed,
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

// pickTargetsFromSamples runs PC sampling on the target for `duration`,
// returns the top K non-noise function symbols, and stderr-logs each pick so
// the user can see what the auto-mode chose without parsing the JSON report.
func pickTargetsFromSamples(ctx context.Context, pid int, duration time.Duration, freq uint64, k int, filterRegex string) ([]coz.SymbolHit, error) {
	if pid <= 0 {
		return nil, fmt.Errorf("auto-pick requires -pid")
	}
	var noise *regexp.Regexp
	if filterRegex != "" {
		re, err := regexp.Compile(filterRegex)
		if err != nil {
			return nil, fmt.Errorf("compile -auto-filter: %w", err)
		}
		noise = re
	}
	fmt.Fprintf(os.Stderr, "auto-pick: sampling pid %d for %s at %d Hz...\n", pid, duration, freq)
	hits, err := coz.AutoPick(ctx, pid, duration, freq, k, noise)
	if err != nil {
		return nil, err
	}
	if len(hits) == 0 {
		return nil, fmt.Errorf("no non-noise symbols sampled")
	}
	return hits, nil
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
