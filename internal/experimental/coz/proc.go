// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0
//go:build linux

package coz

import (
	"fmt"
	"os"
	"strconv"
)

type procTIDSource struct{}

func (procTIDSource) TIDs(pid int, maxThreads int) ([]int, error) {
	if pid <= 0 {
		return nil, errMissingPID
	}
	if maxThreads <= 0 {
		return nil, fmt.Errorf("max threads must be positive: %d", maxThreads)
	}
	entries, err := os.ReadDir(fmt.Sprintf("/proc/%d/task", pid))
	if err != nil {
		return nil, fmt.Errorf("read task directory: %w", err)
	}
	tids := make([]int, 0, len(entries))
	for _, entry := range entries {
		if !entry.IsDir() {
			continue
		}
		tid, err := strconv.Atoi(entry.Name())
		if err != nil {
			continue
		}
		tids = append(tids, tid)
		if len(tids) > maxThreads {
			return nil, fmt.Errorf("thread count exceeds max_threads (%d)", maxThreads)
		}
	}
	if len(tids) == 0 {
		return nil, fmt.Errorf("no tids found for pid %d", pid)
	}
	return tids, nil
}
