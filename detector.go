// SPDX-License-Identifier: Apache-2.0
package main

import "regexp"

// Detector is the pluggable PII/injection-detection seam.
//
// This is the boundary that isolates the one Python-leaning dependency (Microsoft Presidio)
// from the rest of the block. v0 ships RegexDetector (pure Go, no external process); v1 can
// swap in a Presidio-backed detector — run as a sidecar/subprocess or via an ONNX runtime —
// without touching the guard, the contract, or the IPC. "Adopt the tool behind a seam;
// don't let it dictate the substrate."
type Detector interface {
	// RedactPII returns the text with PII replaced by <LABEL> placeholders, plus a
	// "pii:<LABEL>" flag per category found.
	RedactPII(text string) (redacted string, flags []string)
	// DetectInjection returns ["injection_suspected"] if the text looks like a
	// context-poisoning / prompt-injection attempt, else nil.
	DetectInjection(text string) []string
}

// RegexDetector is the v0 stand-in for Presidio: a few high-signal recognizers.
type RegexDetector struct {
	pii       []labeledPattern
	injection []*regexp.Regexp
}

type labeledPattern struct {
	label   string
	pattern *regexp.Regexp
}

func NewRegexDetector() *RegexDetector {
	return &RegexDetector{
		pii: []labeledPattern{
			{"EMAIL", regexp.MustCompile(`[\w.+-]+@[\w-]+\.[\w.-]+`)},
			{"US_SSN", regexp.MustCompile(`\b\d{3}-\d{2}-\d{4}\b`)},
			{"CREDIT_CARD", regexp.MustCompile(`\b(?:\d[ -]?){13,16}\b`)},
			{"API_KEY", regexp.MustCompile(`\b(?:sk|AKIA|ghp|xox[baprs])[-_A-Za-z0-9]{8,}`)},
		},
		injection: []*regexp.Regexp{
			regexp.MustCompile(`(?i)ignore\b[\w\s]*\binstructions`),
			regexp.MustCompile(`(?i)disregard\b[\w\s]*\binstructions`),
			regexp.MustCompile(`(?i)system prompt`),
			regexp.MustCompile(`(?i)</?(?:system|instructions)>`),
		},
	}
}

func (d *RegexDetector) RedactPII(text string) (string, []string) {
	var flags []string
	out := text
	for _, lp := range d.pii {
		if lp.pattern.MatchString(out) {
			flags = append(flags, "pii:"+lp.label)
			out = lp.pattern.ReplaceAllString(out, "<"+lp.label+">")
		}
	}
	return out, flags
}

func (d *RegexDetector) DetectInjection(text string) []string {
	for _, p := range d.injection {
		if p.MatchString(text) {
			return []string{"injection_suspected"}
		}
	}
	return nil
}

// NativeDetector is the v1 production Detector backend chosen by the memory-guard tracer
// (ADR-002): Go-native, in-process, zero new third-party dependencies — it stays inside the
// Go standard library, preserving ADR-001 §2's stdlib-only property. No Presidio sidecar, no
// ONNX runtime, no IPC round-trip on the memory hot path.
//
// It is a distinct, swappable Detector that reaches parity with RegexDetector on the v0
// categories (EMAIL / US_SSN / CREDIT_CARD / API_KEY + the v0 injection patterns) by composing
// the same high-signal recognizers internally. Broadening recall (Presidio-grade NER breadth)
// is a detector-internal task (004) behind RedactPII — no guard / IPC / contract impact, because
// the choice lives entirely behind the unchanged Detector seam.
type NativeDetector struct {
	base *RegexDetector
}

// NewNativeDetector builds the Go-native in-process detector (ADR-002).
func NewNativeDetector() *NativeDetector {
	return &NativeDetector{base: NewRegexDetector()}
}

// RedactPII satisfies the unchanged Detector interface — PII → <LABEL> placeholders + pii:<LABEL>
// flags, in-process, no external call.
func (d *NativeDetector) RedactPII(text string) (string, []string) {
	return d.base.RedactPII(text)
}

// DetectInjection satisfies the unchanged Detector interface — ["injection_suspected"] or nil,
// in-process, no external call.
func (d *NativeDetector) DetectInjection(text string) []string {
	return d.base.DetectInjection(text)
}
