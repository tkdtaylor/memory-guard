// SPDX-License-Identifier: Apache-2.0
package main

import (
	"math"
	"sync"
)

// detector_size.go: the SECOND WriteInspector implementation (task 019 / ADR-018).
//
// SizeAnomalyDetector flags a write whose byte size deviates far from the recent history of
// writes under the SAME identity key. An unexpectedly large write (relative to that key's own
// pattern) can signal exfil staging (an agent parking a large blob for later retrieval) or a
// bulk poisoning payload (many injected instructions in one write). The signal is behavioral,
// not lexical: no single write is inherently suspicious out of context, only one anomalous
// relative to its key's own baseline, which is exactly why it needs the stateful WriteInspector
// seam (task 018) and not the stateless Detector seam (detector.go).
//
// The finding is ADDITIVE and NON-BLOCKING: Inspect appends size_anomaly_suspected to the
// validate_write flags array, but the guard never lets a behavioral flag change allow /
// stored_id (ADR-016 §3). Whether a size anomaly should block, quarantine, or require review is
// a policy-engine decision, out of scope here and re-homed to task 022.
//
// Everything here is stdlib-only (math / sync); go.mod stays require-free.

// sizeAnomalyFlag is the additive flag value appended to validate_write's flags array when a
// write's size trips the sigma test. NON-BLOCKING: the write still stores.
const sizeAnomalyFlag = "size_anomaly_suspected"

// Documented defaults (ADR-018 §2). A zero-value SizeAnomalyConfig resolves to these; no field
// is ever left at a value that would divide-by-zero or always-flag.
const (
	defaultSizeWindowSize     = 20
	defaultSizeSigmaThreshold = 3.0
	defaultSizeMinSamples     = 5
)

// SizeAnomalyConfig tunes the rolling-baseline size detector. A zero-value struct resolves every
// field to its documented default via NewSizeAnomalyDetector.
type SizeAnomalyConfig struct {
	// WindowSize is the number of most-recent write sizes retained per key (the bounded ring
	// buffer capacity). Older samples are evicted once the buffer is full. Default 20.
	WindowSize int
	// SigmaThreshold is the number of standard deviations from the key's rolling mean beyond
	// which a write is flagged (strict >). Default 3.0.
	SigmaThreshold float64
	// MinSamples is the minimum number of prior samples a key's buffer must already hold before
	// any write can be flagged (cold-start guard). Default 5.
	MinSamples int
}

// SizeAnomalyDetector implements WriteInspector. It keeps, per identity key, a bounded ring
// buffer of the most recent write sizes and flags a write whose size deviates beyond
// SigmaThreshold standard deviations from that key's rolling mean. State is internal to the seam
// (never in guard.go or the MemoryStore) and guarded by its own mutex, so it is safe for
// concurrent Inspect calls without relying on the guard's lock (REQ-009).
type SizeAnomalyDetector struct {
	mu sync.Mutex

	windowSize     int
	sigmaThreshold float64
	minSamples     int

	// buffers maps an identity key to its bounded, insertion-ordered ring of recent write sizes
	// (bytes). Each key's buffer and statistics are fully independent (REQ-005).
	buffers map[string][]int
}

// NewSizeAnomalyDetector builds the detector, resolving any non-positive config field to its
// documented default (WindowSize=20, SigmaThreshold=3.0, MinSamples=5). This guarantees a
// zero-value SizeAnomalyConfig is a valid default config, never a divide-by-zero or always-flag.
func NewSizeAnomalyDetector(cfg SizeAnomalyConfig) *SizeAnomalyDetector {
	windowSize := cfg.WindowSize
	if windowSize < 1 {
		windowSize = defaultSizeWindowSize
	}
	sigma := cfg.SigmaThreshold
	if sigma <= 0 {
		sigma = defaultSizeSigmaThreshold
	}
	minSamples := cfg.MinSamples
	if minSamples < 1 {
		minSamples = defaultSizeMinSamples
	}
	return &SizeAnomalyDetector{
		windowSize:     windowSize,
		sigmaThreshold: sigma,
		minSamples:     minSamples,
		buffers:        map[string][]int{},
	}
}

// Inspect implements WriteInspector. It sizes the write on len(content), then applies the
// COMPARE-THEN-UPDATE rule (ADR-018 §2): the anomaly test for this sample runs against the
// baseline built from the key's EXISTING buffer (samples before this one), and only afterwards
// is this sample appended (evicting the oldest once at WindowSize capacity). So an anomalous
// sample never dilutes the baseline it is compared against.
//
// It returns [sizeAnomalyFlag] iff the key's buffer already holds at least MinSamples samples AND
// abs(size-mean) > SigmaThreshold*stddev (strict >). Zero-variance edge (stddev==0, every prior
// sample identical): any size != mean flags, size == mean does not. Otherwise nil.
//
// ctx.SourceClass is deliberately NOT consulted: size anomaly is orthogonal to provenance in this
// task's scope. Only ctx.Key groups the baselines.
func (d *SizeAnomalyDetector) Inspect(content string, ctx WriteContext) []string {
	size := len(content)

	d.mu.Lock()
	defer d.mu.Unlock()

	buf := d.buffers[ctx.Key]

	var flags []string
	if len(buf) >= d.minSamples {
		mean, stddev := meanStddev(buf)
		if math.Abs(float64(size)-mean) > d.sigmaThreshold*stddev {
			flags = []string{sizeAnomalyFlag}
		}
	}

	// Compare-then-update: append AFTER the test, evicting the oldest sample at capacity.
	buf = append(buf, size)
	if len(buf) > d.windowSize {
		buf = buf[len(buf)-d.windowSize:]
	}
	d.buffers[ctx.Key] = buf

	return flags
}

// bufferFor returns a copy of the current size ring for a key. Test-visible accessor used to
// assert the compare-then-update eviction ordering (TC-001) without racing the internal state.
func (d *SizeAnomalyDetector) bufferFor(key string) []int {
	d.mu.Lock()
	defer d.mu.Unlock()
	src := d.buffers[key]
	out := make([]int, len(src))
	copy(out, src)
	return out
}

// meanStddev returns the arithmetic mean and the POPULATION standard deviation (divide by n, not
// n-1) of a non-empty integer sample. Population stddev is the right measure here: the buffer IS
// the whole observed window, not a sample of a larger set. Callers gate on len(xs) >= MinSamples
// (>= 1), so n is never zero.
func meanStddev(xs []int) (mean, stddev float64) {
	n := float64(len(xs))
	sum := 0.0
	for _, x := range xs {
		sum += float64(x)
	}
	mean = sum / n
	var sq float64
	for _, x := range xs {
		diff := float64(x) - mean
		sq += diff * diff
	}
	return mean, math.Sqrt(sq / n)
}

// combinedInspector fans one accepted write out to several WriteInspectors and unions their
// flags. Its slice of wrapped inspectors is immutable after construction, so it adds no shared
// mutable state of its own and needs no locking beyond what each wrapped inspector provides
// (REQ-009).
type combinedInspector struct {
	inspectors []WriteInspector
}

// CombineInspectors returns a WriteInspector that, on each Inspect, calls every wrapped inspector
// IN ORDER and returns the order-stable, deduplicated UNION of their flags. It lets an operator
// wire more than one behavioral detector through the single WithWriteInspector field without
// MemoryGuard gaining a second field (REQ-007). nil inspectors are dropped at construction so a
// disabled detector (buildWriteInspector returning nil) composes cleanly. Combining does not
// change any wrapped detector's own per-call behavior or state: each still sees every accepted
// write exactly once, in order. CombineInspectors() with no (non-nil) inspectors returns a
// no-op whose Inspect always returns nil.
func CombineInspectors(inspectors ...WriteInspector) WriteInspector {
	kept := make([]WriteInspector, 0, len(inspectors))
	for _, in := range inspectors {
		if in != nil {
			kept = append(kept, in)
		}
	}
	return &combinedInspector{inspectors: kept}
}

// Inspect implements WriteInspector: fan out to each wrapped inspector in order, union the flags.
func (c *combinedInspector) Inspect(content string, ctx WriteContext) []string {
	var union []string
	seen := map[string]struct{}{}
	for _, in := range c.inspectors {
		for _, f := range in.Inspect(content, ctx) {
			if _, ok := seen[f]; ok {
				continue
			}
			seen[f] = struct{}{}
			union = append(union, f)
		}
	}
	return union
}
