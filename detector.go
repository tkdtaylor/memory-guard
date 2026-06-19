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
