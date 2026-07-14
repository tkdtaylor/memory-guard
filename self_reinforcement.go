// SPDX-License-Identifier: Apache-2.0
package main

import (
	"regexp"
	"strings"
	"sync"
	"time"
)

// self_reinforcement.go: the first WriteInspector implementation (task 018 / ADR-016).
//
// SelfReinforcementDetector flags an agent poisoning itself through repetitive self-authored
// writes: when an incoming write's token-set similarity to enough recent same-subject writes
// meets a threshold, it emits self_reinforcement_suspected. The signal is behavioral (a
// repetition pattern over a cooldown window), not lexical, which is exactly why it needs the
// stateful WriteInspector seam and not the pure-function Detector seam.
//
// Everything here is stdlib-only (regexp / strings / sync / time); go.mod stays require-free.

// selfReinforcementFlag is the additive flag value appended to validate_write's flags array
// when the repetition condition trips. It is NON-BLOCKING (ADR-016 §3): the write still stores.
const selfReinforcementFlag = "self_reinforcement_suspected"

// humanAuthoredSourceClass is the single provenance value that OPTS A WRITE OUT of
// self-reinforcement scrutiny. Human repetition is out of scope for this detector. Every other
// source-class value, including an absent hint, an empty string, and any unrecognized value,
// defaults to agent-authored (fail-closed toward scrutiny, ADR-016 §4 / REQ-007).
const humanAuthoredSourceClass = "human_authored"

// Default wiring parameters (ADR-016 §2). These are what main.go's serve/write path ships;
// tests override them via the functional options below.
const (
	defaultSimilarityThreshold  = 0.85
	defaultCooldown             = 5 * time.Minute
	defaultMaxSelfWrites        = 3
	defaultMaxHistoryPerSubject = 256
)

// tokenPattern splits content into lowercased alphanumeric token runs. Anything else
// (whitespace, punctuation) is a separator, so "successfully," and "successfully" tokenize
// identically. Deterministic and dependency-free.
var tokenPattern = regexp.MustCompile(`[a-z0-9]+`)

// writeRecord is one remembered write in a subject's bounded history: the token set of the
// content plus the instant it was seen (for cooldown-window eviction).
type writeRecord struct {
	tokens map[string]struct{}
	at     time.Time
}

// SelfReinforcementDetector implements WriteInspector. It keeps a bounded per-subject history of
// recent writes and flags when a new write is a near-duplicate of enough of them within the
// cooldown window. State is internal to the seam (never in guard.go or the MemoryStore).
type SelfReinforcementDetector struct {
	mu sync.Mutex

	// similarityThreshold is the minimum token-set overlap coefficient at which two writes count
	// as near-duplicates (0..1). A pair scoring >= this threshold contributes to the count.
	similarityThreshold float64
	// cooldown is the window within which prior writes still count toward the repetition total.
	// A prior write older than cooldown (relative to the current write) is evicted, not counted.
	cooldown time.Duration
	// maxSelfWrites is the number of prior in-window near-duplicates at (or above) which the
	// incoming write is flagged. With the default 3, the 4th near-duplicate in a window is the
	// first to flag.
	maxSelfWrites int
	// maxHistoryPerSubject caps a single subject's remembered writes so memory cannot grow
	// without bound even inside one cooldown window; the oldest records are trimmed first.
	maxHistoryPerSubject int
	// clock supplies the current time; injectable so cooldown tests are deterministic.
	clock func() time.Time

	// history maps a subject key to its bounded, time-ordered write records.
	history map[string][]writeRecord
}

// SelfReinforcementOption configures a SelfReinforcementDetector at construction.
type SelfReinforcementOption func(*SelfReinforcementDetector)

// WithSimilarityThreshold sets the near-duplicate token-set overlap threshold (0..1).
func WithSimilarityThreshold(t float64) SelfReinforcementOption {
	return func(d *SelfReinforcementDetector) { d.similarityThreshold = t }
}

// WithCooldown sets the repetition window: prior writes older than this (relative to the
// current write) are evicted and no longer count.
func WithCooldown(c time.Duration) SelfReinforcementOption {
	return func(d *SelfReinforcementDetector) { d.cooldown = c }
}

// WithMaxSelfWrites sets the count of prior in-window near-duplicates at which a write is flagged.
func WithMaxSelfWrites(n int) SelfReinforcementOption {
	return func(d *SelfReinforcementDetector) { d.maxSelfWrites = n }
}

// WithMaxHistoryPerSubject sets the hard per-subject history size cap (bounded memory).
func WithMaxHistoryPerSubject(n int) SelfReinforcementOption {
	return func(d *SelfReinforcementDetector) { d.maxHistoryPerSubject = n }
}

// WithClock injects a deterministic clock (test-only; production uses time.Now).
func WithClock(clock func() time.Time) SelfReinforcementOption {
	return func(d *SelfReinforcementDetector) { d.clock = clock }
}

// NewSelfReinforcementDetector builds the detector with the ADR-016 default wiring values
// (similarity 0.85, cooldown 5m, max self-writes 3), overridable via options.
func NewSelfReinforcementDetector(opts ...SelfReinforcementOption) *SelfReinforcementDetector {
	d := &SelfReinforcementDetector{
		similarityThreshold:  defaultSimilarityThreshold,
		cooldown:             defaultCooldown,
		maxSelfWrites:        defaultMaxSelfWrites,
		maxHistoryPerSubject: defaultMaxHistoryPerSubject,
		clock:                time.Now,
		history:              map[string][]writeRecord{},
	}
	for _, o := range opts {
		o(d)
	}
	if d.clock == nil {
		d.clock = time.Now
	}
	if d.maxHistoryPerSubject < 1 {
		d.maxHistoryPerSubject = defaultMaxHistoryPerSubject
	}
	return d
}

// Inspect implements WriteInspector. It returns [selfReinforcementFlag] when the incoming write
// is a near-duplicate of at least maxSelfWrites prior same-subject writes inside the cooldown
// window; otherwise nil. A non-agent-authored write (source-class human_authored) is never
// scrutinized and always returns nil.
//
// Side effect: the incoming write is recorded in the subject's bounded history so subsequent
// writes can count it. This is the state the detection depends on; it lives entirely here.
func (d *SelfReinforcementDetector) Inspect(content string, ctx WriteContext) []string {
	if !treatedAsAgentAuthored(ctx.SourceClass) {
		return nil
	}

	now := d.clock()
	tokens := tokenSet(content)

	d.mu.Lock()
	defer d.mu.Unlock()

	// Evict stale records for this subject (older than the cooldown relative to now), then count
	// how many surviving records are near-duplicates of the incoming write.
	recent := d.pruneLocked(ctx.Key, now)
	similar := 0
	for _, r := range recent {
		if overlapCoefficient(tokens, r.tokens) >= d.similarityThreshold {
			similar++
		}
	}

	// Record the incoming write AFTER counting (it must not count against itself), then enforce
	// the per-subject size cap so memory stays bounded even within one window.
	recent = append(recent, writeRecord{tokens: tokens, at: now})
	if len(recent) > d.maxHistoryPerSubject {
		recent = recent[len(recent)-d.maxHistoryPerSubject:]
	}
	d.history[ctx.Key] = recent

	if similar >= d.maxSelfWrites {
		return []string{selfReinforcementFlag}
	}
	return nil
}

// pruneLocked drops records for key that are older than the cooldown window relative to now and
// returns the surviving slice. A record counts as in-window when (now - record.at) < cooldown;
// a record exactly cooldown-old or older is evicted. Caller holds d.mu.
func (d *SelfReinforcementDetector) pruneLocked(key string, now time.Time) []writeRecord {
	recs := d.history[key]
	if len(recs) == 0 {
		return recs
	}
	kept := recs[:0]
	for _, r := range recs {
		if now.Sub(r.at) < d.cooldown {
			kept = append(kept, r)
		}
	}
	d.history[key] = kept
	return kept
}

// historySize returns the number of records currently retained for a subject key. Test-visible
// accessor used to assert the per-subject history stays bounded (ADR-016 §2 / TC-004).
func (d *SelfReinforcementDetector) historySize(key string) int {
	d.mu.Lock()
	defer d.mu.Unlock()
	return len(d.history[key])
}

// similarCount returns how many retained in-window records for key are near-duplicates of content
// at time now. It prunes stale records exactly as Inspect does, but does NOT record content, so a
// test can assert the exact window-boundary count without perturbing history (TC-004 edge). It
// shares pruneLocked and overlapCoefficient with Inspect, so it observes the same computation.
func (d *SelfReinforcementDetector) similarCount(key, content string, now time.Time) int {
	tokens := tokenSet(content)
	d.mu.Lock()
	defer d.mu.Unlock()
	recent := d.pruneLocked(key, now)
	n := 0
	for _, r := range recent {
		if overlapCoefficient(tokens, r.tokens) >= d.similarityThreshold {
			n++
		}
	}
	return n
}

// treatedAsAgentAuthored reports whether a write with the given source-class hint is subject to
// self-reinforcement scrutiny. Only the explicit human_authored value opts out; everything else,
// including an absent or unrecognized hint, defaults to agent-authored (ADR-016 §4 / REQ-007).
func treatedAsAgentAuthored(sourceClass string) bool {
	return strings.TrimSpace(sourceClass) != humanAuthoredSourceClass
}

// tokenSet lowercases content and returns the set of its alphanumeric token runs.
func tokenSet(content string) map[string]struct{} {
	toks := tokenPattern.FindAllString(strings.ToLower(content), -1)
	set := make(map[string]struct{}, len(toks))
	for _, t := range toks {
		set[t] = struct{}{}
	}
	return set
}

// overlapCoefficient is the token-set overlap coefficient (Szymkiewicz-Simpson):
// |A intersection B| / min(|A|, |B|), in [0, 1]. It is the set-based similarity consistent with
// the task's near-duplicate corpus (ADR-016 §2); an empty set on either side scores 0.
func overlapCoefficient(a, b map[string]struct{}) float64 {
	if len(a) == 0 || len(b) == 0 {
		return 0
	}
	// Iterate the smaller set for the intersection count.
	small, large := a, b
	if len(large) < len(small) {
		small, large = large, small
	}
	inter := 0
	for t := range small {
		if _, ok := large[t]; ok {
			inter++
		}
	}
	return float64(inter) / float64(len(small))
}
