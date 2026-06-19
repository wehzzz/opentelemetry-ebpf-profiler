// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0
//go:build linux

package coz

import (
	"bufio"
	"context"
	"debug/elf"
	"fmt"
	"os"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"time"

	"go.opentelemetry.io/ebpf-profiler/libpf"
	"go.opentelemetry.io/ebpf-profiler/libpf/pfelf"
)

// DefaultNoiseFilter matches symbol names that are almost never the user's
// hot path: dynamic linker, libc internals, pthread shim. Excluded by default
// from auto-pick because their slope is noisy and they are rarely actionable
// targets even when frequently sampled.
var DefaultNoiseFilter = regexp.MustCompile(`^(_dl_|__libc_|__GI_|pthread_|_GLOBAL_|__pthread_|__cxa_|__static_initialization|__do_global)`)

// SymbolHit is one auto-pick candidate: a function name with the binary it
// lives in and the sample count that landed inside it during calibration.
type SymbolHit struct {
	Symbol     string
	BinaryPath string
	Count      uint64
}

// AutoPick samples the target PID for `duration`, symbolizes every PC, filters
// noise symbols, and returns the top K functions by sample count.
//
// freqHz controls the perf sampling frequency (e.g. 999). The function is
// intentionally synchronous: callers pass a deadline via ctx.
func AutoPick(ctx context.Context, pid int, duration time.Duration, freqHz uint64, k int, noiseFilter *regexp.Regexp) ([]SymbolHit, error) {
	if noiseFilter == nil {
		noiseFilter = DefaultNoiseFilter
	}
	sampler := NewSampler(pid, freqHz)
	if err := sampler.Start(); err != nil {
		return nil, fmt.Errorf("start sampler: %w", err)
	}
	defer sampler.Close()

	timer := time.NewTimer(duration)
	defer timer.Stop()
	select {
	case <-ctx.Done():
		sampler.Stop()
		return nil, ctx.Err()
	case <-timer.C:
	}
	sampler.Stop()
	sampler.Drain()
	counts := sampler.Counts()
	if len(counts) == 0 {
		return nil, fmt.Errorf("no PC samples captured for pid %d in %s (raise sampling frequency or duration)", pid, duration)
	}

	symbols, err := resolveProcessSymbols(pid)
	if err != nil {
		return nil, fmt.Errorf("resolve symbols for pid %d: %w", pid, err)
	}
	if len(symbols) == 0 {
		return nil, fmt.Errorf("no symbols resolvable for pid %d", pid)
	}
	sort.Slice(symbols, func(i, j int) bool { return symbols[i].StartAddr < symbols[j].StartAddr })

	hits := make(map[string]*SymbolHit)
	for pc, count := range counts {
		sym, ok := lookupSymbol(symbols, pc)
		if !ok {
			continue
		}
		key := sym.BinaryPath + "\x00" + sym.Name
		h, exists := hits[key]
		if !exists {
			h = &SymbolHit{Symbol: sym.Name, BinaryPath: sym.BinaryPath}
			hits[key] = h
		}
		h.Count += count
	}

	out := make([]SymbolHit, 0, len(hits))
	for _, h := range hits {
		if noiseFilter.MatchString(h.Symbol) {
			continue
		}
		out = append(out, *h)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Count > out[j].Count })
	if len(out) > k {
		out = out[:k]
	}
	return out, nil
}

// resolvedSymbol is one function known to be loaded somewhere in the target's
// address space, with its runtime [Start, End) range.
type resolvedSymbol struct {
	Name       string
	BinaryPath string
	StartAddr  uint64
	EndAddr    uint64
}

// resolveProcessSymbols walks /proc/<pid>/maps and, for each unique
// executable mapping with a backing file, parses the binary's symbol table
// and translates each function's vaddr to a runtime address using the
// mapping's bias. Returns one resolvedSymbol per function known to the loader.
func resolveProcessSymbols(pid int) ([]resolvedSymbol, error) {
	mappings, err := parseProcMaps(pid)
	if err != nil {
		return nil, err
	}
	type fileMaps struct {
		path     string
		segments []procMapping
	}
	byFile := make(map[string]*fileMaps)
	for _, m := range mappings {
		if !m.Exec || m.Path == "" || strings.HasPrefix(m.Path, "[") {
			continue
		}
		entry, ok := byFile[m.Path]
		if !ok {
			entry = &fileMaps{path: m.Path}
			byFile[m.Path] = entry
		}
		entry.segments = append(entry.segments, m)
	}

	var out []resolvedSymbol
	for path, fm := range byFile {
		ef, err := pfelf.Open(path)
		if err != nil {
			// A missing or unreadable file is not fatal: just skip it.
			continue
		}
		syms, err := symbolsForFile(ef, fm.segments)
		ef.Close()
		if err != nil {
			continue
		}
		for _, s := range syms {
			s.BinaryPath = path
			out = append(out, s)
		}
	}
	return out, nil
}

// symbolsForFile collects every STT_FUNC symbol (with size > 0) from `ef`
// and translates its vaddr to a runtime address for each provided mapping.
// A symbol can appear multiple times if its segment is mapped twice.
func symbolsForFile(ef *pfelf.File, mappings []procMapping) ([]resolvedSymbol, error) {
	type biasedRange struct {
		bias        int64
		loVaddr     uint64
		hiVaddr     uint64
	}
	var ranges []biasedRange
	for _, m := range mappings {
		load := loadForMapping(ef, m)
		if load == nil {
			continue
		}
		bias := int64(m.Start) - int64(load.Vaddr) - int64(m.FileOffset-load.Off)
		ranges = append(ranges, biasedRange{
			bias:    bias,
			loVaddr: load.Vaddr,
			hiVaddr: load.Vaddr + load.Memsz,
		})
	}
	if len(ranges) == 0 {
		return nil, nil
	}

	var out []resolvedSymbol
	visitor := func(sym libpf.Symbol) bool {
		if sym.Size == 0 || sym.Name == "" {
			return true
		}
		for _, r := range ranges {
			value := uint64(sym.Address)
			if value < r.loVaddr || value >= r.hiVaddr {
				continue
			}
			start := uint64(int64(value) + r.bias)
			out = append(out, resolvedSymbol{
				Name:      string(sym.Name),
				StartAddr: start,
				EndAddr:   start + sym.Size,
			})
		}
		return true
	}
	// Try the static symbol table first (richer for user binaries with debug
	// info or non-stripped builds), then fall back to dynamic symbols.
	if err := ef.VisitSymbols(visitor); err != nil {
		_ = ef.VisitDynamicSymbols(visitor)
	} else if len(out) == 0 {
		_ = ef.VisitDynamicSymbols(visitor)
	}
	return out, nil
}

// loadForMapping returns the LOAD program header whose file range covers the
// mapping's file offset. The address-space arithmetic for each mapping uses
// the matching load header's vaddr; without it we can't translate symbol
// vaddrs to runtime addresses correctly for non-PIE binaries.
func loadForMapping(ef *pfelf.File, m procMapping) *pfelf.Prog {
	for i := range ef.Progs {
		p := &ef.Progs[i]
		if p.Type != elf.PT_LOAD {
			continue
		}
		if p.Flags&elf.PF_X == 0 {
			continue
		}
		if m.FileOffset >= p.Off && m.FileOffset < p.Off+p.Filesz {
			return p
		}
	}
	return nil
}

// lookupSymbol does a binary search in the sorted runtime-address list for
// the symbol whose [Start, End) interval contains pc. Returns false when no
// resolved symbol covers pc (unmapped page, JIT, alien library not loaded
// during calibration).
func lookupSymbol(symbols []resolvedSymbol, pc uint64) (*resolvedSymbol, bool) {
	if len(symbols) == 0 {
		return nil, false
	}
	i := sort.Search(len(symbols), func(i int) bool { return symbols[i].StartAddr > pc })
	if i == 0 {
		return nil, false
	}
	cand := &symbols[i-1]
	if pc < cand.StartAddr || pc >= cand.EndAddr {
		return nil, false
	}
	return cand, true
}

// procMapping is one line of /proc/<pid>/maps.
type procMapping struct {
	Start      uint64
	End        uint64
	FileOffset uint64
	Path       string
	Read       bool
	Write      bool
	Exec       bool
	Private    bool
}

func parseProcMaps(pid int) ([]procMapping, error) {
	f, err := os.Open(fmt.Sprintf("/proc/%d/maps", pid))
	if err != nil {
		return nil, err
	}
	defer f.Close()
	var out []procMapping
	sc := bufio.NewScanner(f)
	sc.Buffer(make([]byte, 1<<20), 1<<20)
	for sc.Scan() {
		m, ok := parseMapsLine(sc.Text())
		if ok {
			out = append(out, m)
		}
	}
	return out, sc.Err()
}

func parseMapsLine(line string) (procMapping, bool) {
	// Format: "start-end perms offset dev inode path".
	fields := strings.SplitN(line, " ", 6)
	if len(fields) < 5 {
		return procMapping{}, false
	}
	addrRange := strings.SplitN(fields[0], "-", 2)
	if len(addrRange) != 2 {
		return procMapping{}, false
	}
	start, err := strconv.ParseUint(addrRange[0], 16, 64)
	if err != nil {
		return procMapping{}, false
	}
	end, err := strconv.ParseUint(addrRange[1], 16, 64)
	if err != nil {
		return procMapping{}, false
	}
	perms := fields[1]
	if len(perms) < 4 {
		return procMapping{}, false
	}
	offset, err := strconv.ParseUint(fields[2], 16, 64)
	if err != nil {
		return procMapping{}, false
	}
	path := ""
	if len(fields) >= 6 {
		path = strings.TrimSpace(fields[5])
	}
	return procMapping{
		Start:      start,
		End:        end,
		FileOffset: offset,
		Path:       path,
		Read:       perms[0] == 'r',
		Write:      perms[1] == 'w',
		Exec:       perms[2] == 'x',
		Private:    perms[3] == 'p',
	}, true
}
