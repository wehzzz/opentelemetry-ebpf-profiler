// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

//go:build linux

// coz-verify launches a Coz benchmark binary, attaches the coz-runner against
// it with auto-pick + rotation, parses the JSON report, and asserts that the
// per-target slopes match the benchmark's documented ground truth. Used as
// the regression check that proves the controller actually produces
// causally-meaningful results.
package main

import (
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"os/exec"
	"os/signal"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
	"time"
)

// targetRanking is the subset of coz.TargetRanking we need to read from the
// report. We re-declare it here to avoid pulling the (Linux-only) coz package
// into this binary's build graph beyond JSON shape compatibility.
type targetRanking struct {
	TargetName  string  `json:"target_name"`
	Slope       float64 `json:"slope"`
	SlopeCILow  float64 `json:"slope_ci_low"`
	SlopeCIHigh float64 `json:"slope_ci_high"`
	Status      string  `json:"status"`
	Detail      string  `json:"status_detail"`
}

type report struct {
	RoundsRun     int             `json:"rounds_run"`
	TargetsRanked []targetRanking `json:"targets_ranked"`
}

type benchSpec struct {
	binary           string
	progressSymbol   string
	autoFilter       string
	expectations     func(ranks []targetRanking) []string // returns failure messages; empty = pass
	autoTargets      int
	cpuPin           string // optional taskset -c value
	requiredBaseline int    // sanity check: fail if median baseline progress under this
}

func main() {
	os.Exit(run())
}

func run() int {
	var (
		benchName    string
		benchesDir   string
		runnerPath   string
		bpfObject    string
		budget       time.Duration
		warmup       time.Duration
		reportPath   string
		cpuPin       string
		extraTargets int
	)
	flag.StringVar(&benchName, "bench", "", "Benchmark to run: useful_useless | lockheavy.")
	flag.StringVar(&benchesDir, "bench-dir", ".", "Directory containing the benchmark binaries.")
	flag.StringVar(&runnerPath, "runner", "/tmp/coz-runner", "Path to the coz-runner binary.")
	flag.StringVar(&bpfObject, "bpf-object", "support/ebpf/coz.ebpf.amd64", "Path to the Coz eBPF object.")
	flag.DurationVar(&budget, "budget", 60*time.Second, "Wall-clock budget for the experiment.")
	flag.DurationVar(&warmup, "warmup", 500*time.Millisecond, "Time to wait after launching the benchmark before attaching the runner.")
	flag.StringVar(&reportPath, "report", "/tmp/coz-verify-report.json", "Where the runner writes the report.")
	flag.StringVar(&cpuPin, "cpu-pin", "", "Optional taskset -c value to constrain the benchmark to fewer cores (e.g. 0,1).")
	flag.IntVar(&extraTargets, "auto-targets", 0, "Override the auto-targets count (0 = use the bench default).")
	flag.Parse()

	bench, ok := benches()[benchName]
	if !ok {
		fmt.Fprintf(os.Stderr, "unknown -bench %q (options: useful_useless, lockheavy)\n", benchName)
		return 2
	}
	if cpuPin != "" {
		bench.cpuPin = cpuPin
	}
	if extraTargets > 0 {
		bench.autoTargets = extraTargets
	}
	binaryPath, err := filepath.Abs(filepath.Join(benchesDir, bench.binary))
	if err != nil {
		fmt.Fprintf(os.Stderr, "resolve binary path: %v\n", err)
		return 2
	}
	if _, err := os.Stat(binaryPath); err != nil {
		fmt.Fprintf(os.Stderr, "benchmark binary not found at %s — run `make -C tools/coz-bench`\n", binaryPath)
		return 2
	}

	ctx, cancel := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer cancel()

	fmt.Fprintf(os.Stderr, "[verify] launching benchmark %s (pin=%q)\n", binaryPath, bench.cpuPin)
	benchCmd := launchBench(ctx, binaryPath, bench.cpuPin)
	if benchCmd == nil {
		return 1
	}
	defer killBench(benchCmd)

	time.Sleep(warmup)
	if benchCmd.ProcessState != nil {
		fmt.Fprintf(os.Stderr, "[verify] benchmark exited during warmup\n")
		return 1
	}

	pid := benchCmd.Process.Pid
	fmt.Fprintf(os.Stderr, "[verify] running coz-runner against pid %d for %s\n", pid, budget)
	rep, err := runRunner(ctx, runnerPath, bpfObject, pid, binaryPath, bench, budget, reportPath)
	if err != nil {
		fmt.Fprintf(os.Stderr, "[verify] coz-runner failed: %v\n", err)
		return 1
	}

	fmt.Fprintln(os.Stderr, "[verify] ranked targets:")
	for _, r := range rep.TargetsRanked {
		fmt.Fprintf(os.Stderr, "  %-32s slope=%+.5f CI=[%+.5f, %+.5f] status=%s %s\n",
			r.TargetName, r.Slope, r.SlopeCILow, r.SlopeCIHigh, r.Status, r.Detail)
	}

	failures := bench.expectations(rep.TargetsRanked)
	if len(failures) == 0 {
		fmt.Println("PASS")
		return 0
	}
	fmt.Println("FAIL")
	for _, f := range failures {
		fmt.Printf("  - %s\n", f)
	}
	return 1
}

func benches() map[string]benchSpec {
	return map[string]benchSpec{
		"useful_useless": {
			binary:           "bench_useful_useless",
			progressSymbol:   "bench_progress",
			autoFilter:       `^(_dl_|__libc_|__GI_|pthread_|_GLOBAL_|sem_|nanosleep|clock_)`,
			autoTargets:      4,
			cpuPin:           "0",
			requiredBaseline: 50,
			expectations: func(ranks []targetRanking) []string {
				return assertUsefulVsUseless(ranks)
			},
		},
		"lockheavy": {
			binary:           "bench_lockheavy",
			progressSymbol:   "bench_progress",
			autoFilter:       `^(_dl_|__libc_|__GI_|pthread_|_GLOBAL_|sem_|nanosleep|clock_)`,
			autoTargets:      5,
			// 2 cores: mutex contention is meaningful (multiple workers can
			// fight for the lock at the same time). 1 core would serialize
			// everything anyway and erase the contention signal.
			cpuPin:           "0,1",
			requiredBaseline: 50,
			expectations: func(ranks []targetRanking) []string {
				return assertLockheavy(ranks)
			},
		},
		"coz_toy": {
			binary:           "bench_coz_toy",
			progressSymbol:   "bench_progress",
			autoFilter:       `^(_dl_|__libc_|__GI_|pthread_|_GLOBAL_|sem_|nanosleep|clock_)`,
			autoTargets:      3,
			cpuPin:           "0",
			requiredBaseline: 50,
			expectations: func(ranks []targetRanking) []string {
				// Upstream toy: a() does 2x the work of b() and gates the
				// join. Expected ranking: bench_a > bench_b.
				return assertHigher(ranks, "bench_a", "bench_b")
			},
		},
		"coz_pc": {
			binary:           "bench_coz_pc",
			progressSymbol:   "bench_progress",
			autoFilter:       `^(_dl_|__libc_|__GI_|pthread_|_GLOBAL_|sem_|nanosleep|clock_)`,
			autoTargets:      4,
			cpuPin:           "0,1",
			requiredBaseline: 50,
			expectations: func(ranks []targetRanking) []string {
				// Upstream producer_consumer: 5 producers feed a 10-slot
				// queue read by 3 consumers. Producers gate progress when
				// the queue stays empty. Expected: producer_step > consumer_step.
				return assertHigher(ranks, "bench_producer_step", "bench_consumer_step")
			},
		},
		"coz_lock": {
			binary:           "bench_coz_lock",
			progressSymbol:   "bench_progress",
			autoFilter:       `^(_dl_|__libc_|__GI_|pthread_|_GLOBAL_|sem_|nanosleep|clock_)`,
			autoTargets:      3,
			cpuPin:           "0,1",
			requiredBaseline: 50,
			expectations: func(ranks []targetRanking) []string {
				// Upstream lock_test: critical_work runs under a global
				// mutex; local_work runs lock-free. Expected: critical_work
				// has higher slope (it's the scaling bottleneck).
				return assertHigher(ranks, "bench_critical_work", "bench_local_work")
			},
		},
	}
}

func assertUsefulVsUseless(ranks []targetRanking) []string {
	var fails []string
	useful := findRank(ranks, "bench_useful_work")
	useless := findRank(ranks, "bench_useless_work")
	if useful == nil {
		fails = append(fails, "auto-pick missed bench_useful_work — target list does not include it")
		return fails
	}
	if useless == nil {
		fails = append(fails, "auto-pick missed bench_useless_work — target list does not include it")
		return fails
	}
	if useful.Status != "ok" {
		fails = append(fails, fmt.Sprintf("bench_useful_work status %q (%s) — expected ok", useful.Status, useful.Detail))
	}
	// Ground truth: useful_work is on the critical path of progress;
	// useless_work is not. With CPU contention, pausing useless during
	// useful's execution frees CPU for useful → useful's slope must be
	// strictly higher than useless's, and the difference must clear the CI
	// noise floor.
	if useful.Slope <= useless.Slope {
		fails = append(fails, fmt.Sprintf("expected slope(useful)=%+.5f > slope(useless)=%+.5f (useful is the only one on the critical path of progress)",
			useful.Slope, useless.Slope))
	}
	jointHalfWidth := halfWidth(useful) + halfWidth(useless)
	if useful.Slope-useless.Slope < jointHalfWidth {
		fails = append(fails, fmt.Sprintf("difference slope(useful)−slope(useless)=%+.5f does not clear the noise floor %+.5f — increase -budget for more rounds",
			useful.Slope-useless.Slope, jointHalfWidth))
	}
	return fails
}

func assertLockheavy(ranks []targetRanking) []string {
	var fails []string
	serialized := findRank(ranks, "bench_serialized_step")
	parallel := findRank(ranks, "bench_parallel_step")
	noise := findRank(ranks, "bench_noise_work")
	if serialized == nil {
		fails = append(fails, "auto-pick missed bench_serialized_step")
		return fails
	}
	if serialized.Status != "ok" {
		fails = append(fails, fmt.Sprintf("bench_serialized_step status %q (%s) — expected ok", serialized.Status, serialized.Detail))
	}
	// Ground truth: the serialized critical section is the scaling
	// bottleneck. Virtual speedup of the serialized step should not hurt
	// progress (pausing other workers that are waiting on the lock is
	// free), while virtual speedup of the parallel step DOES hurt (pausing
	// peers in parallel work loses concurrent throughput). So serialized
	// must rank above parallel and noise.
	if parallel != nil && parallel.Status == "ok" && parallel.Slope >= serialized.Slope {
		fails = append(fails, fmt.Sprintf("expected slope(serialized)=%+.5f > slope(parallel)=%+.5f — the serialized step is the bottleneck",
			serialized.Slope, parallel.Slope))
	}
	if noise != nil && noise.Status == "ok" && noise.Slope >= serialized.Slope {
		fails = append(fails, fmt.Sprintf("expected slope(serialized)=%+.5f > slope(noise)=%+.5f — noise is irrelevant to progress",
			serialized.Slope, noise.Slope))
	}
	return fails
}

func halfWidth(r *targetRanking) float64 {
	return (r.SlopeCIHigh - r.SlopeCILow) / 2
}

// assertHigher checks that target `winner` has a higher slope than `loser`
// and that the difference exceeds the joint CI noise floor. Used for the
// generic two-target ranking benches (toy, producer_consumer, lock_test).
func assertHigher(ranks []targetRanking, winner, loser string) []string {
	var fails []string
	w := findRank(ranks, winner)
	l := findRank(ranks, loser)
	if w == nil {
		fails = append(fails, fmt.Sprintf("auto-pick missed %s — target list does not include it", winner))
		return fails
	}
	if l == nil {
		fails = append(fails, fmt.Sprintf("auto-pick missed %s — target list does not include it", loser))
		return fails
	}
	if w.Status != "ok" {
		fails = append(fails, fmt.Sprintf("%s status %q (%s) — expected ok", winner, w.Status, w.Detail))
	}
	if w.Slope <= l.Slope {
		fails = append(fails, fmt.Sprintf("expected slope(%s)=%+.5f > slope(%s)=%+.5f",
			winner, w.Slope, loser, l.Slope))
	}
	joint := halfWidth(w) + halfWidth(l)
	if w.Slope-l.Slope < joint {
		fails = append(fails, fmt.Sprintf("difference slope(%s)−slope(%s)=%+.5f does not clear noise floor %+.5f",
			winner, loser, w.Slope-l.Slope, joint))
	}
	return fails
}

func findRank(ranks []targetRanking, name string) *targetRanking {
	for i := range ranks {
		if ranks[i].TargetName == name {
			return &ranks[i]
		}
	}
	return nil
}

func launchBench(ctx context.Context, binaryPath string, cpuPin string) *exec.Cmd {
	args := []string{}
	exe := binaryPath
	if cpuPin != "" {
		exe = "taskset"
		args = append(args, "-c", cpuPin, binaryPath)
	}
	cmd := exec.CommandContext(ctx, exe, args...)
	cmd.Stdout = os.Stderr
	cmd.Stderr = os.Stderr
	cmd.SysProcAttr = &syscall.SysProcAttr{Setpgid: true}
	if err := cmd.Start(); err != nil {
		fmt.Fprintf(os.Stderr, "launch %s: %v\n", binaryPath, err)
		return nil
	}
	return cmd
}

func killBench(cmd *exec.Cmd) {
	if cmd == nil || cmd.Process == nil {
		return
	}
	_ = syscall.Kill(-cmd.Process.Pid, syscall.SIGKILL)
	_, _ = cmd.Process.Wait()
}

func runRunner(ctx context.Context, runner, bpf string, pid int, binary string, bench benchSpec, budget time.Duration, reportPath string) (*report, error) {
	args := []string{
		"-pid", strconv.Itoa(pid),
		"-progress", fmt.Sprintf("uprobe:%s:%s", binary, bench.progressSymbol),
		"-auto-targets", strconv.Itoa(bench.autoTargets),
		"-budget", budget.String(),
		"-rounds", "0",
		"-report", reportPath,
		"-bpf-object", bpf,
		// s=100 collapses throughput to ~0 on these benches because the
		// full-pause path can catch the target's own thread between
		// iterations and stall it for the whole window. v0 keeps the
		// upper-bound path opt-in for diagnostic runs only.
		"-speedups", "0,5,10,20",
	}
	if bench.autoFilter != "" {
		args = append(args, "-auto-filter", bench.autoFilter)
	}
	cmd := exec.CommandContext(ctx, runner, args...)
	cmd.Stdout = os.Stderr
	cmd.Stderr = os.Stderr
	if err := cmd.Run(); err != nil {
		return nil, fmt.Errorf("coz-runner: %w", err)
	}
	data, err := os.ReadFile(reportPath)
	if err != nil {
		return nil, fmt.Errorf("read report: %w", err)
	}
	var rep report
	if err := json.Unmarshal(data, &rep); err != nil {
		return nil, fmt.Errorf("parse report: %w", err)
	}
	if rep.RoundsRun == 0 {
		return nil, fmt.Errorf("no rounds completed — likely benchmark exited or controller failed early. Report at %s", reportPath)
	}
	return &rep, nil
}

// stringer helper to make slope-CI lines compact in logs.
func compactCI(low, high float64) string {
	return fmt.Sprintf("[%s, %s]", trimTrailing(low), trimTrailing(high))
}

func trimTrailing(x float64) string {
	s := strconv.FormatFloat(x, 'f', 6, 64)
	if strings.Contains(s, ".") {
		s = strings.TrimRight(s, "0")
		s = strings.TrimRight(s, ".")
	}
	return s
}
