// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

//go:build linux

package coz

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
	"golang.org/x/sys/unix"
)

func TestPtraceDelayForSpeedup(t *testing.T) {
	backend := NewPtraceBackend(100 * time.Millisecond)

	require.Equal(t, time.Duration(0), backend.delayForSpeedup(0))
	require.Equal(t, 25*time.Millisecond, backend.delayForSpeedup(20))
	require.Equal(t, 100*time.Millisecond, backend.delayForSpeedup(50))
}

func TestIsThreadGone(t *testing.T) {
	require.True(t, isThreadGone(fmt.Errorf("wrapped: %w", unix.ESRCH)))
	require.True(t, isThreadGone(fmt.Errorf("wrapped: %w", unix.ECHILD)))
	require.False(t, isThreadGone(unix.EPERM))
}

func TestPickTIDRoundRobin(t *testing.T) {
	backend := NewPtraceBackend(time.Millisecond)
	tids := []int{11, 22, 33}

	require.Equal(t, 11, backend.pickTID(tids))
	require.Equal(t, 22, backend.pickTID(tids))
	require.Equal(t, 33, backend.pickTID(tids))
	require.Equal(t, 11, backend.pickTID(tids))
}

func TestProcThreadState(t *testing.T) {
	path := filepath.Join(t.TempDir(), "stat")
	require.NoError(t, os.WriteFile(path, []byte("1234 (coz demo worker) R 1 2 3"), 0o644))

	state, err := parseProcThreadState(path)
	require.NoError(t, err)
	require.Equal(t, byte('R'), state)
}

func TestProcThreadStateRejectsMalformedStat(t *testing.T) {
	path := filepath.Join(t.TempDir(), "stat")
	require.NoError(t, os.WriteFile(path, []byte("1234 coz-demo R"), 0o644))

	_, err := parseProcThreadState(path)
	require.ErrorContains(t, err, "malformed proc stat")
}

func TestApplySkipsWhenNoRunnableCandidate(t *testing.T) {
	backend := NewPtraceBackend(time.Millisecond)
	backend.attached[1234] = struct{}{}

	stats, err := backend.Apply(context.Background(), func(context.Context) (TargetState, error) {
		return TargetState{ActiveTIDs: map[int]ThreadState{}}, nil
	}, 20, time.Millisecond)

	require.NoError(t, err)
	require.Zero(t, stats.Attempts)
	require.Zero(t, stats.DelayedThreads)
}
