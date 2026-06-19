// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0
//go:build linux

package coz

import (
	"math"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
)

func makeWindow(targetID uint32, targetName string, speedup int, pointID uint32, tput float64, progress uint64) WindowResult {
	return WindowResult{
		TargetID:   targetID,
		TargetName: targetName,
		Speedup:    speedup,
		Progress:   map[uint32]uint64{pointID: progress},
		Throughput: map[uint32]float64{pointID: tput},
		Duration:   time.Second,
	}
}

func TestAnalyzeReportPositiveSlope(t *testing.T) {
	// Linear: at speedup s%, throughput rises by 1% per percent speedup.
	// Baseline throughput = 100, so cell mean = 100 * (1 + 0.01*s).
	// With 3 reps per cell and 4 speedup levels there are 12 windows.
	report := &Report{}
	for _, s := range []int{0, 10, 20, 50} {
		for rep := 0; rep < 3; rep++ {
			tput := 100.0 * (1.0 + 0.01*float64(s))
			report.Windows = append(report.Windows,
				makeWindow(1, "useful_work", s, 1, tput, uint64(tput)*1000))
		}
	}
	AnalyzeReport(report, 0)
	require.Len(t, report.TargetsRanked, 1)
	r := report.TargetsRanked[0]
	require.Equal(t, StatusOK, r.Status, r.StatusDetail)
	require.InDelta(t, 0.01, r.Slope, 1e-6)
	require.True(t, r.SlopeCILow > 0, "slope CI should be entirely positive: low=%f high=%f", r.SlopeCILow, r.SlopeCIHigh)
}

func TestAnalyzeReportZeroSlopeIncludesZero(t *testing.T) {
	// Noisy data with zero true slope; CI should include zero.
	report := &Report{}
	noise := []float64{1.02, 0.98, 1.01, 0.99, 1.00, 1.03, 0.97}
	idx := 0
	for _, s := range []int{0, 10, 20, 50, 100} {
		for rep := 0; rep < 5; rep++ {
			n := noise[idx%len(noise)]
			idx++
			tput := 100.0 * n
			report.Windows = append(report.Windows,
				makeWindow(2, "useless_work", s, 1, tput, uint64(tput)*1000))
		}
	}
	AnalyzeReport(report, 0)
	require.Len(t, report.TargetsRanked, 1)
	r := report.TargetsRanked[0]
	require.NotEqual(t, StatusInsufficientData, r.Status)
	require.LessOrEqual(t, r.SlopeCILow, 0.0, "zero-slope target should not exclude 0 on the low side: %+v", r)
	require.GreaterOrEqual(t, r.SlopeCIHigh, 0.0, "zero-slope target should not exclude 0 on the high side: %+v", r)
}

func TestAnalyzeReportInsufficientDataFlagged(t *testing.T) {
	// Baseline median below threshold → no slope reported.
	report := &Report{}
	for _, s := range []int{0, 10} {
		report.Windows = append(report.Windows,
			makeWindow(3, "rare", s, 1, 1, 1))
	}
	AnalyzeReport(report, 10)
	require.Len(t, report.TargetsRanked, 1)
	require.Equal(t, StatusInsufficientData, report.TargetsRanked[0].Status)
}

func TestAnalyzeReportRanksByMagnitude(t *testing.T) {
	report := &Report{}
	// Target A: slope ~ 0.02
	for _, s := range []int{0, 10, 20, 50, 100} {
		for rep := 0; rep < 3; rep++ {
			tput := 100.0 * (1.0 + 0.02*float64(s))
			report.Windows = append(report.Windows,
				makeWindow(1, "alpha", s, 1, tput, uint64(tput)*1000))
		}
	}
	// Target B: slope ~ -0.005
	for _, s := range []int{0, 10, 20, 50, 100} {
		for rep := 0; rep < 3; rep++ {
			tput := 100.0 * (1.0 - 0.005*float64(s))
			report.Windows = append(report.Windows,
				makeWindow(2, "beta", s, 1, tput, uint64(tput)*1000))
		}
	}
	AnalyzeReport(report, 0)
	require.Len(t, report.TargetsRanked, 2)
	require.Equal(t, "alpha", report.TargetsRanked[0].TargetName)
	require.Equal(t, "beta", report.TargetsRanked[1].TargetName)
	require.Greater(t, math.Abs(report.TargetsRanked[0].Slope), math.Abs(report.TargetsRanked[1].Slope))
}
