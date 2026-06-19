// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0
//go:build linux

package coz

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"strconv"
	"sync/atomic"
	"unsafe"

	"golang.org/x/sys/unix"
)

const (
	// ringBufferPages is the data-area size of each per-TID perf ring in 4 KiB
	// pages. 8 pages = 32 KiB — large enough for ~4 k samples/window at ~1 kHz
	// without losing records, small enough to mmap many TIDs cheaply.
	ringBufferPages = 8
	// perfRecordSample is the type ID for PERF_RECORD_SAMPLE — the only record
	// type we decode. Other records (mmap, comm, exit) are skipped by header
	// size.
	perfRecordSample = 9
)

// Sampler is a lightweight per-TID CPU sampler. It opens one
// perf_event_open(PERF_TYPE_SOFTWARE, PERF_COUNT_SW_CPU_CLOCK) per attached
// TID, samples instruction pointer at the configured frequency, and exposes a
// raw `pid_tid → pc → count` aggregation for the user-space symbolizer.
//
// The implementation is deliberately self-contained: no eBPF, no shared
// infrastructure with the production profiler. v0 trades sophistication for
// debuggability.
type Sampler struct {
	freqHz   uint64
	pageSize int
	fds      []int
	rings    [][]byte
	tids     []int
	pid      int
	counts   map[uint64]uint64
	started  bool
}

// NewSampler prepares per-TID perf events on the target PID at the given
// sample frequency in Hz (typical: 99 or 999).
func NewSampler(pid int, freqHz uint64) *Sampler {
	return &Sampler{
		freqHz:   freqHz,
		pageSize: os.Getpagesize(),
		pid:      pid,
		counts:   make(map[uint64]uint64),
	}
}

// Start enumerates the target's threads and opens a perf fd per thread.
// Threads spawned *after* Start are not captured — that is a deliberate v0
// simplification.
func (s *Sampler) Start() error {
	tids, err := enumerateTIDs(s.pid)
	if err != nil {
		return fmt.Errorf("enumerate tids: %w", err)
	}
	if len(tids) == 0 {
		return fmt.Errorf("pid %d has no threads", s.pid)
	}
	attr := &unix.PerfEventAttr{
		Type:        unix.PERF_TYPE_SOFTWARE,
		Size:        uint32(unsafe.Sizeof(unix.PerfEventAttr{})),
		Config:      unix.PERF_COUNT_SW_CPU_CLOCK,
		Sample:      s.freqHz,
		Sample_type: unix.PERF_SAMPLE_IP,
		Bits:        unix.PerfBitDisabled | unix.PerfBitFreq | unix.PerfBitExcludeKernel | unix.PerfBitExcludeHv,
		Wakeup:      1,
	}
	mmapSize := (1 + ringBufferPages) * s.pageSize
	for _, tid := range tids {
		fd, openErr := unix.PerfEventOpen(attr, tid, -1, -1, unix.PERF_FLAG_FD_CLOEXEC)
		if openErr != nil {
			// A thread can exit between enumeration and open; ignore those.
			if errors.Is(openErr, unix.ESRCH) {
				continue
			}
			_ = s.Close()
			return fmt.Errorf("perf_event_open tid %d: %w", tid, openErr)
		}
		ring, mErr := unix.Mmap(fd, 0, mmapSize, unix.PROT_READ|unix.PROT_WRITE, unix.MAP_SHARED)
		if mErr != nil {
			unix.Close(fd)
			_ = s.Close()
			return fmt.Errorf("mmap tid %d ring: %w", tid, mErr)
		}
		s.fds = append(s.fds, fd)
		s.rings = append(s.rings, ring)
		s.tids = append(s.tids, tid)
	}
	if len(s.fds) == 0 {
		return fmt.Errorf("no threads to sample for pid %d", s.pid)
	}
	for _, fd := range s.fds {
		if err := unix.IoctlSetInt(fd, unix.PERF_EVENT_IOC_RESET, 0); err != nil {
			_ = s.Close()
			return fmt.Errorf("perf reset: %w", err)
		}
		if err := unix.IoctlSetInt(fd, unix.PERF_EVENT_IOC_ENABLE, 0); err != nil {
			_ = s.Close()
			return fmt.Errorf("perf enable: %w", err)
		}
	}
	s.started = true
	return nil
}

// Stop disables sampling on every fd. The ring buffers remain mmap'd so Drain
// can read out any pending records.
func (s *Sampler) Stop() {
	for _, fd := range s.fds {
		_ = unix.IoctlSetInt(fd, unix.PERF_EVENT_IOC_DISABLE, 0)
	}
}

// Drain reads all pending PERF_RECORD_SAMPLE records from every ring and
// accumulates them into the PC → count map. Must be called after Stop. Safe
// to call multiple times; counts accumulate across calls.
func (s *Sampler) Drain() {
	for i, ring := range s.rings {
		s.drainRing(ring)
		// Touch i so the linter does not complain about an unused index in
		// future extensions (per-TID counts not needed for the v0 aggregator).
		_ = i
	}
}

// Counts returns the accumulated PC → count map. The returned map is owned by
// the caller; the sampler keeps its own internal map separate.
func (s *Sampler) Counts() map[uint64]uint64 {
	out := make(map[uint64]uint64, len(s.counts))
	for pc, c := range s.counts {
		out[pc] = c
	}
	return out
}

// Close detaches every fd and unmaps every ring. Safe to call multiple times.
func (s *Sampler) Close() error {
	var joined error
	for _, ring := range s.rings {
		if err := unix.Munmap(ring); err != nil {
			joined = errors.Join(joined, err)
		}
	}
	s.rings = nil
	for _, fd := range s.fds {
		if err := unix.Close(fd); err != nil {
			joined = errors.Join(joined, err)
		}
	}
	s.fds = nil
	s.tids = nil
	s.started = false
	return joined
}

// drainRing walks the lockless ring buffer described at
// `tools/include/uapi/linux/perf_event.h` and increments s.counts[ip] for
// every PERF_RECORD_SAMPLE encountered. The protocol is: read Data_head with
// acquire semantics, walk records from Data_tail to head, then publish a new
// Data_tail with release semantics.
func (s *Sampler) drainRing(ring []byte) {
	page := (*unix.PerfEventMmapPage)(unsafe.Pointer(&ring[0]))
	dataOff := int(page.Data_offset)
	dataSize := int(page.Data_size)
	if dataSize == 0 {
		return
	}
	headPtr := (*uint64)(unsafe.Pointer(&page.Data_head))
	tailPtr := (*uint64)(unsafe.Pointer(&page.Data_tail))
	head := atomic.LoadUint64(headPtr)
	tail := atomic.LoadUint64(tailPtr)
	runtime.KeepAlive(page)

	for tail < head {
		var hdr [8]byte
		readRing(ring, dataOff, dataSize, int(tail), hdr[:])
		recType := *(*uint32)(unsafe.Pointer(&hdr[0]))
		recSize := *(*uint16)(unsafe.Pointer(&hdr[6]))
		if recSize == 0 {
			// Defensive: skip malformed record to avoid an infinite loop.
			break
		}
		if recType == perfRecordSample {
			var body [8]byte
			readRing(ring, dataOff, dataSize, int(tail)+8, body[:])
			ip := *(*uint64)(unsafe.Pointer(&body[0]))
			s.counts[ip]++
		}
		tail += uint64(recSize)
	}
	atomic.StoreUint64(tailPtr, tail)
}

// readRing copies n bytes from the data area starting at `offset` (a byte
// position relative to the start of the *data* area, not the mmap). It
// transparently handles the ring's wraparound at dataSize.
func readRing(ring []byte, dataOff, dataSize, offset int, out []byte) {
	pos := offset % dataSize
	if pos+len(out) <= dataSize {
		copy(out, ring[dataOff+pos:dataOff+pos+len(out)])
		return
	}
	first := dataSize - pos
	copy(out[:first], ring[dataOff+pos:dataOff+pos+first])
	copy(out[first:], ring[dataOff:dataOff+len(out)-first])
}

func enumerateTIDs(pid int) ([]int, error) {
	entries, err := os.ReadDir(fmt.Sprintf("/proc/%d/task", pid))
	if err != nil {
		return nil, err
	}
	out := make([]int, 0, len(entries))
	for _, e := range entries {
		tid, err := strconv.Atoi(filepath.Base(e.Name()))
		if err != nil {
			continue
		}
		out = append(out, tid)
	}
	return out, nil
}
