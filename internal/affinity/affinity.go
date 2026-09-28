//go:build linux

// Package affinity pins a goroutine to a CPU. (Copied from packetio's
// examples/internal/affinity, which is not importable.)
package affinity

import (
	"fmt"
	"os"
	"runtime"
	"strconv"
	"strings"

	"golang.org/x/sys/unix"
)

// Pin locks the calling goroutine to its operating system thread and moves
// that thread to the given CPU. It stays there until the goroutine ends.
// A negative cpu pins nothing.
func Pin(cpu int) error {
	if cpu < 0 {
		return nil
	}
	runtime.LockOSThread()
	var set unix.CPUSet
	set.Zero()
	set.Set(cpu)
	if err := unix.SchedSetaffinity(0, &set); err != nil {
		runtime.UnlockOSThread()
		return fmt.Errorf("pinning to cpu %d: %w", cpu, err)
	}
	return nil
}

// Exclude removes cpus from the calling thread's affinity mask. Called from
// the main goroutine before any packet goroutine starts, it is inherited by
// every thread the Go runtime creates afterwards, so the runtime's threads
// (crypto workers, the TUN reader, GC) stay off the cores that receive
// goroutines spin on: a thread time-sliced against a spinning core sees
// millisecond pauses, which is a full ring of arrivals.
func Exclude(cpus []int) error {
	if len(cpus) == 0 {
		return nil
	}
	var set unix.CPUSet
	if err := unix.SchedGetaffinity(0, &set); err != nil {
		return fmt.Errorf("reading affinity: %w", err)
	}
	for _, c := range cpus {
		set.Clear(c)
	}
	if set.Count() == 0 {
		return fmt.Errorf("excluding %v leaves no cpu for the runtime", cpus)
	}
	// Apply to every thread that already exists, not just this one.
	tids, _ := os.ReadDir("/proc/self/task")
	for _, t := range tids {
		tid, err := strconv.Atoi(t.Name())
		if err != nil {
			continue
		}
		if err := unix.SchedSetaffinity(tid, &set); err != nil {
			return fmt.Errorf("excluding cpus %v: %w", cpus, err)
		}
	}
	return nil
}

// Parse turns a list like "4,6,8-11" into CPU numbers.
func Parse(s string) ([]int, error) {
	if strings.TrimSpace(s) == "" {
		return nil, nil
	}
	var cpus []int
	for _, part := range strings.Split(s, ",") {
		part = strings.TrimSpace(part)
		lo, hi, isRange := strings.Cut(part, "-")
		first, err := strconv.Atoi(strings.TrimSpace(lo))
		if err != nil {
			return nil, fmt.Errorf("cpu list %q: %w", s, err)
		}
		last := first
		if isRange {
			if last, err = strconv.Atoi(strings.TrimSpace(hi)); err != nil {
				return nil, fmt.Errorf("cpu list %q: %w", s, err)
			}
		}
		if last < first {
			return nil, fmt.Errorf("cpu list %q: range %s is backwards", s, part)
		}
		for c := first; c <= last; c++ {
			cpus = append(cpus, c)
		}
	}
	return cpus, nil
}
