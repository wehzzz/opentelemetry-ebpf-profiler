// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

//go:build linux

package coz

import (
	"bytes"
	"context"
	"fmt"
	"os"

	"github.com/cilium/ebpf"

	"go.opentelemetry.io/ebpf-profiler/rlimit"
)

// LoadProgramSet loads a standalone Coz eBPF object from disk.
func LoadProgramSet(_ context.Context, path string) (*ProgramSet, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("read coz bpf object %q: %w", path, err)
	}
	spec, err := ebpf.LoadCollectionSpecFromReader(bytes.NewReader(data))
	if err != nil {
		return nil, fmt.Errorf("load coz bpf spec %q: %w", path, err)
	}
	restoreRlimit, err := rlimit.MaximizeMemlock()
	if err != nil {
		return nil, fmt.Errorf("adjust rlimit: %w", err)
	}
	defer restoreRlimit()

	coll, err := ebpf.NewCollection(spec)
	if err != nil {
		return nil, fmt.Errorf("load coz bpf collection: %w", err)
	}
	return NewProgramSet(coll.Programs, coll.Maps), nil
}
