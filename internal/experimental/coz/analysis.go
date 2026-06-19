// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0
//go:build linux

package coz

import (
	"fmt"
	"math"
	"sort"
)

// Status enum for TargetRanking. Strings, not ints, because the rendered
// report is consumed by humans first and downstream tools second.
const (
	StatusOK               = "ok"
	StatusInsufficientData = "insufficient_data"
	StatusHighVariance     = "high_variance"
)

// AnalyzeReport computes the per-target slope (relative throughput change per
// percent of virtual speedup) for every progress point and fills
// report.TargetsRanked. The slope sign is the actionable signal:
//
//	slope > 0  → virtually speeding up the target helps progress → optimize.
//	slope ≈ 0  → target is hot but not on the critical path of progress.
//	slope < 0  → target is anti-correlated; the perturbation is hurting progress
//	             via a side channel (e.g. consumer thread being stalled too).
//
// Confidence intervals use White's HC1 heteroscedasticity-consistent standard
// errors because per-cell variance at high speedups dominates baseline
// variance — plain OLS SEs systematically underestimate the CI width.
func AnalyzeReport(report *Report, minBaselineProgress float64) {
	if report == nil || len(report.Windows) == 0 {
		return
	}
	if minBaselineProgress <= 0 {
		minBaselineProgress = defaultMinBaselineProg
	}

	type seriesKey struct {
		targetID uint32
		pointID  uint32
	}
	type sample struct {
		speedup int
		tput    float64
	}
	series := make(map[seriesKey][]sample)
	targetNames := make(map[uint32]string)
	pointBaselineMeans := make(map[seriesKey]float64)
	pointBaselineCounts := make(map[seriesKey][]float64)

	for _, w := range report.Windows {
		targetNames[w.TargetID] = w.TargetName
		for pointID, tput := range w.Throughput {
			k := seriesKey{w.TargetID, pointID}
			series[k] = append(series[k], sample{w.Speedup, tput})
			if w.Speedup == 0 {
				pointBaselineCounts[k] = append(pointBaselineCounts[k], float64(w.Progress[pointID]))
			}
		}
	}

	for k, samples := range series {
		baselineThroughputs := make([]float64, 0)
		for _, s := range samples {
			if s.speedup == 0 {
				baselineThroughputs = append(baselineThroughputs, s.tput)
			}
		}
		if len(baselineThroughputs) > 0 {
			pointBaselineMeans[k] = mean(baselineThroughputs)
		}
	}

	rankings := make([]TargetRanking, 0, len(series))
	for k, samples := range series {
		baseline := pointBaselineMeans[k]
		baselineMedian := median(pointBaselineCounts[k])
		r := TargetRanking{
			TargetID:       k.targetID,
			TargetName:     targetNames[k.targetID],
			PointID:        k.pointID,
			SampleCount:    len(samples),
			BaselineMedian: baselineMedian,
		}
		if baselineMedian < minBaselineProgress {
			r.Status = StatusInsufficientData
			r.StatusDetail = fmt.Sprintf("baseline median %.0f < threshold %.0f progress events per window",
				baselineMedian, minBaselineProgress)
			rankings = append(rankings, r)
			continue
		}
		if baseline == 0 {
			r.Status = StatusInsufficientData
			r.StatusDetail = "no baseline throughput recorded"
			rankings = append(rankings, r)
			continue
		}
		xs := make([]float64, 0, len(samples))
		ys := make([]float64, 0, len(samples))
		for _, s := range samples {
			xs = append(xs, float64(s.speedup))
			ys = append(ys, (s.tput-baseline)/baseline)
		}
		slope, slopeSE, residualStd, n := fitLineHC1(xs, ys)
		if n < 3 {
			r.Status = StatusInsufficientData
			r.StatusDetail = fmt.Sprintf("only %d data points", n)
			rankings = append(rankings, r)
			continue
		}
		// 95% CI: ±1.96 × SE. With n=10 reps × ~5 speedups = ~50 obs, df is
		// well past the regime where Student's t materially differs from z.
		halfWidth := 1.96 * slopeSE
		r.Slope = slope
		r.SlopeCILow = slope - halfWidth
		r.SlopeCIHigh = slope + halfWidth
		r.PredictedGain20 = slope * 20
		r.PredictedGain100 = slope * 100
		r.Status = StatusOK
		// Flag as HighVariance if the residual standard deviation is large
		// relative to typical observed deltas. We use the standardized
		// residual scale (residualStd / max|y|): when residuals are >50% of
		// the dynamic range we should not trust the slope sign.
		dynRange := 0.0
		for _, y := range ys {
			if math.Abs(y) > dynRange {
				dynRange = math.Abs(y)
			}
		}
		if dynRange > 0 && residualStd/dynRange > 0.5 {
			r.Status = StatusHighVariance
			r.StatusDetail = fmt.Sprintf("residual std %.3f vs |y|max %.3f (ratio %.2f)",
				residualStd, dynRange, residualStd/dynRange)
		}
		rankings = append(rankings, r)
	}

	// Rank: actionable targets first (OK status, positive slope, then by slope
	// magnitude); then HighVariance; then InsufficientData. Within each tier
	// sort by |slope| desc so the operator sees the biggest moves first.
	sort.SliceStable(rankings, func(i, j int) bool {
		ri, rj := rankings[i], rankings[j]
		if ri.Status != rj.Status {
			return statusOrder(ri.Status) < statusOrder(rj.Status)
		}
		return math.Abs(ri.Slope) > math.Abs(rj.Slope)
	})
	report.TargetsRanked = rankings
}

func statusOrder(s string) int {
	switch s {
	case StatusOK:
		return 0
	case StatusHighVariance:
		return 1
	default:
		return 2
	}
}

// fitLineHC1 fits y = α + β·x by OLS, then computes a White HC1
// heteroscedasticity-consistent standard error for β. Returns
// (slope, slope_se, residual_stddev, n).
//
// HC1 is OLS-SE × √( (n / (n−2)) · Σ(xᵢ−x̄)²·εᵢ² / [Σ(xᵢ−x̄)²]² ). When variance
// is homoscedastic this collapses to the textbook OLS SE — so using it is
// strictly safer than plain OLS and free in CPU cost.
func fitLineHC1(xs, ys []float64) (slope, slopeSE, residualStd float64, n int) {
	n = len(xs)
	if n < 2 || len(ys) != n {
		return 0, math.Inf(1), 0, n
	}
	var sx, sy float64
	for i := range xs {
		sx += xs[i]
		sy += ys[i]
	}
	mx := sx / float64(n)
	my := sy / float64(n)
	var sxx, sxy float64
	for i := range xs {
		dx := xs[i] - mx
		sxx += dx * dx
		sxy += dx * (ys[i] - my)
	}
	if sxx == 0 {
		return 0, math.Inf(1), 0, n
	}
	slope = sxy / sxx
	intercept := my - slope*mx

	var sse float64
	hc1Num := 0.0
	for i := range xs {
		yhat := intercept + slope*xs[i]
		eps := ys[i] - yhat
		sse += eps * eps
		dx := xs[i] - mx
		hc1Num += dx * dx * eps * eps
	}
	if n > 2 {
		residualStd = math.Sqrt(sse / float64(n-2))
	}
	// White HC1: scale by n/(n-2) to be unbiased in small samples.
	if n > 2 {
		varHC1 := (float64(n) / float64(n-2)) * hc1Num / (sxx * sxx)
		slopeSE = math.Sqrt(varHC1)
	} else {
		slopeSE = math.Inf(1)
	}
	return slope, slopeSE, residualStd, n
}

func median(xs []float64) float64 {
	if len(xs) == 0 {
		return 0
	}
	cp := make([]float64, len(xs))
	copy(cp, xs)
	sort.Float64s(cp)
	mid := len(cp) / 2
	if len(cp)%2 == 0 {
		return (cp[mid-1] + cp[mid]) / 2
	}
	return cp[mid]
}
