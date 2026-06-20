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
			// --- v0 recognizers ---
			{"EMAIL", regexp.MustCompile(`[\w.+-]+@[\w-]+\.[\w.-]+`)},
			{"US_SSN", regexp.MustCompile(`\b\d{3}-\d{2}-\d{4}\b`)},
			// CREDIT_CARD: 13–16 consecutive digit groups (spaces/hyphens allowed).
			// Anchored to avoid grabbing the digit run inside an IBAN or phone.
			{"CREDIT_CARD", regexp.MustCompile(`\b(?:\d[ -]?){13,16}\b`)},
			// API_KEY: v0 prefixes (sk / AKIA / ghp / xox[baprs]) plus v1 broader credential
			// prefixes (sk-ant / hf_ / npm_ / pat_ / xp_).  The longer sk-ant alternative is
			// listed before the bare sk alternative so it takes precedence within the alternation;
			// the regex engine will still match sk-ant-... as a whole unit because alternation is
			// left-to-right and ReplaceAllString replaces the full match.
			{"API_KEY", regexp.MustCompile(`\b(?:sk-ant|sk|AKIA|ghp|xox[baprs]|hf_|npm_|pat_|xp_)[-_A-Za-z0-9]{8,}`)},

			// --- v1 recognizers (task 004) ---

			// PHONE: US phone numbers — (NXX) NXX-XXXX, NXX-NXX-XXXX, +1 variants.
			// Requires separators so bare 10-digit strings don't fire.
			{"PHONE", regexp.MustCompile(`\b(?:\+1[\s.-]?)?\(?\d{3}\)?[\s.-]\d{3}[\s.-]\d{4}\b`)},

			// IBAN: starts with 2 uppercase letters + 2 check digits + at least 4 more alphanums.
			// Minimum 8-char total body keeps short codes (e.g. UK car plates "AB12CD") from
			// matching. Real IBANs range from 15 (Norway) to 34 (Malta) characters.
			{"IBAN", regexp.MustCompile(`\b[A-Z]{2}\d{2}[A-Z0-9]{4,30}\b`)},

			// IP_ADDRESS: strict IPv4 (each octet 0–255) or abbreviated IPv6.
			// IPv6 pattern covers full/compressed forms; IPv4 uses strict octet bounds to
			// avoid matching "1.2.3" (3-part semver) — four octets are required.
			{"IP_ADDRESS", regexp.MustCompile(`\b(?:(?:25[0-5]|2[0-4]\d|[01]?\d\d?)\.){3}(?:25[0-5]|2[0-4]\d|[01]?\d\d?)\b|` +
				`(?:[0-9a-fA-F]{1,4}:){7}[0-9a-fA-F]{1,4}|` +
				`(?:[0-9a-fA-F]{1,4}:){1,7}:|` +
				`::(?:[0-9a-fA-F]{1,4}:){0,6}[0-9a-fA-F]{1,4}`)},

			// DOB: date-of-birth in common formats:
			//   MM/DD/YYYY  (e.g. 01/15/1990)
			//   YYYY-MM-DD  (ISO 8601, e.g. 1990-01-15)
			//   DD Mon YYYY (e.g. 15 Jan 1990)
			// Restricted to 19xx/20xx birth years to keep false-positives low.
			{"DOB", regexp.MustCompile(
				`\b(?:0?[1-9]|1[0-2])/(?:0?[1-9]|[12]\d|3[01])/(?:19|20)\d{2}\b|` +
					`\b(?:19|20)\d{2}-(?:0[1-9]|1[0-2])-(?:0[1-9]|[12]\d|3[01])\b|` +
					`\b(?:0?[1-9]|[12]\d|3[01])\s+(?:Jan|Feb|Mar|Apr|May|Jun|Jul|Aug|Sep|Oct|Nov|Dec)[a-z]*\s+(?:19|20)\d{2}\b`)},

			// CREDENTIAL: long hex strings (≥32 hex chars) that look like raw secrets/tokens.
			// Deliberately conservative — requires ≥32 chars to avoid matching UUIDs that happen
			// to be hex (UUIDs contain hyphens which break this pattern, so they don't match).
			{"CREDENTIAL", regexp.MustCompile(`\b[0-9a-fA-F]{32,}\b`)},
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
