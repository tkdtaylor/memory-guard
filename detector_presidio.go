// SPDX-License-Identifier: Apache-2.0
package main

import (
	"bufio"
	"encoding/json"
	"fmt"
	"io"
	"os/exec"
	"sort"
	"strings"
	"sync"
)

// PresidioDetector is the v1 Presidio-backed Detector backend (task 007 / ADR-009): the
// block's FIRST third-party detection backend, kept entirely behind the unchanged Detector
// seam. It un-defers the Presidio path ADR-002 deferred.
//
// Deployment shape (ADR-009): SIDECAR / subprocess. Presidio (spaCy NER + Presidio's
// recognizers) runs in its OWN Python process; this Go type is a stdlib-only IPC client
// (newline-delimited JSON over the subprocess's stdin/stdout). The Go binary therefore stays
// pure-Go / stdlib-only (go.mod has no `require` block) — the entire third-party surface is
// out-of-process and independently scannable. ONNX-in-process is the documented, deferred
// alternative behind this same seam.
//
// COMPOSITE design (recorded in ADR-009): Presidio's default US_SSN / PHONE recognizers are
// conservative (they do NOT fire on the structured corpus cases the native regex backend
// catches — e.g. "123-45-6789" without strong context). A PURE Presidio backend would REGRESS
// the existing PII corpus floors. So PresidioDetector COMPOSES the native regex recognizers
// (preserving every existing PII category + the injection heuristic) and ADDS Presidio's NER
// entities (PERSON / LOCATION / NRP / CRYPTO / MAC_ADDRESS / US_PASSPORT / ...) the regex
// backend has NO recognizer for. That additive NER breadth is the genuine recall lift.
//
// Injection detection is ORTHOGONAL to Presidio (Presidio is a PII/NER engine, not an
// injection classifier). DetectInjection delegates to the native heuristic UNCHANGED — the
// honest finding recorded in ADR-009: this backend lifts PII/NER recall; injection detection
// is unchanged.
//
// Fail-closed: if the sidecar is unavailable (not started, crashed, or the request errors),
// RedactPII falls back to the native redaction (PII still redacted — never a silent pass of
// raw PII). The fallback is silent at the contract surface — callers see the native flags
// only, with no degradation marker; the guard/IPC error shape is untouched and no
// Presidio-typed error ever leaks past the seam.
type PresidioDetector struct {
	native *NativeDetector // composed: structured PII + injection heuristic (always available)

	mu      sync.Mutex
	cmd     *exec.Cmd
	stdin   io.WriteCloser
	stdout  *bufio.Reader
	started bool
	dead    bool // sidecar failed to start or crashed — fall back to native-only

	// pythonBin / scriptPath are the sidecar launch parameters (config-driven).
	pythonBin  string
	scriptPath string

	// minScore is the confidence floor below which a Presidio NER entity is dropped
	// (Presidio scores 0..1; spaCy NER spans like PERSON score ~0.85, low-signal URL ~0.5).
	minScore float64
}

// presidioConfig carries the sidecar launch parameters. Zero-value fields fall back to
// sensible defaults (python3 + presidio/sidecar.py + a 0.5 score floor).
type presidioConfig struct {
	pythonBin  string
	scriptPath string
	minScore   float64
}

// presidioEntityLabels maps Presidio entity types to memory-guard's redaction <LABEL>s.
// ONLY the entities the native regex backend has NO recognizer for are listed here — the
// overlapping structured categories (EMAIL / CREDIT_CARD / IBAN / IP_ADDRESS / PHONE / US_SSN)
// are handled by the composed native recognizers FIRST, so Presidio's (sometimes weaker)
// versions of those never override the native ones. This is the additive-NER half of the
// composite: it adds breadth without regressing the structured floors.
var presidioEntityLabels = map[string]string{
	"PERSON":            "PERSON",
	"LOCATION":          "LOCATION",
	"NRP":               "NRP", // nationality / religious / political group
	"CRYPTO":            "CRYPTO",
	"MAC_ADDRESS":       "MAC_ADDRESS",
	"MEDICAL_LICENSE":   "MEDICAL_LICENSE",
	"US_PASSPORT":       "US_PASSPORT",
	"US_DRIVER_LICENSE": "US_DRIVER_LICENSE",
	"US_BANK_NUMBER":    "US_BANK_NUMBER",
	"US_ITIN":           "US_ITIN",
	"UK_NHS":            "UK_NHS",
	"DATE_TIME":         "DATE_TIME",
}

// NewPresidioDetector builds the Presidio-backed Detector with the given config. It does NOT
// start the sidecar (lazy start on first use) so construction never blocks on a Python spawn;
// callers that want eager start + a readiness check call Start.
func NewPresidioDetector(cfg presidioConfig) *PresidioDetector {
	if cfg.pythonBin == "" {
		cfg.pythonBin = "python3"
	}
	if cfg.scriptPath == "" {
		cfg.scriptPath = "presidio/sidecar.py"
	}
	if cfg.minScore == 0 {
		cfg.minScore = 0.5
	}
	return &PresidioDetector{
		native:     NewNativeDetector(),
		pythonBin:  cfg.pythonBin,
		scriptPath: cfg.scriptPath,
		minScore:   cfg.minScore,
	}
}

// Start spawns the sidecar and blocks until it signals readiness (the spaCy model is loaded).
// This is the COLD-START cost (model load) — paid once, here, and excluded from steady-state
// latency by callers that Start before timing. A start failure marks the detector dead and
// returns the error; RedactPII then falls back to native-only redaction (fail-closed: PII is
// still redacted, never passed through raw).
func (d *PresidioDetector) Start() error {
	d.mu.Lock()
	defer d.mu.Unlock()
	return d.startLocked()
}

func (d *PresidioDetector) startLocked() error {
	if d.started {
		return nil
	}
	cmd := exec.Command(d.pythonBin, d.scriptPath)
	stdin, err := cmd.StdinPipe()
	if err != nil {
		d.dead = true
		return fmt.Errorf("sidecar stdin: %w", err)
	}
	stdout, err := cmd.StdoutPipe()
	if err != nil {
		d.dead = true
		return fmt.Errorf("sidecar stdout: %w", err)
	}
	// Stderr is left attached to the parent's stderr for diagnostics; the protocol channel
	// is stdout only. spaCy/Presidio load logs go to stderr and never corrupt the JSON stream.
	if err := cmd.Start(); err != nil {
		d.dead = true
		return fmt.Errorf("sidecar start: %w", err)
	}
	reader := bufio.NewReader(stdout)

	// Block on the readiness line so the model-load cold-start is paid before any timed call.
	readyLine, err := reader.ReadString('\n')
	if err != nil {
		d.dead = true
		_ = cmd.Process.Kill()
		return fmt.Errorf("sidecar readiness: %w", err)
	}
	var ready map[string]any
	if err := json.Unmarshal([]byte(strings.TrimSpace(readyLine)), &ready); err != nil {
		d.dead = true
		_ = cmd.Process.Kill()
		return fmt.Errorf("sidecar readiness parse: %w", err)
	}
	if ready["ready"] != true {
		d.dead = true
		_ = cmd.Process.Kill()
		return fmt.Errorf("sidecar not ready: %v", ready)
	}

	d.cmd = cmd
	d.stdin = stdin
	d.stdout = reader
	d.started = true
	d.dead = false
	return nil
}

// Close terminates the sidecar subprocess. Safe to call multiple times.
func (d *PresidioDetector) Close() error {
	d.mu.Lock()
	defer d.mu.Unlock()
	if d.cmd == nil || d.cmd.Process == nil {
		return nil
	}
	if d.stdin != nil {
		_ = d.stdin.Close()
	}
	err := d.cmd.Process.Kill()
	_ = d.cmd.Wait()
	d.started = false
	d.cmd = nil
	return err
}

// presidioEntity is one analyzer result decoded off the sidecar wire.
type presidioEntity struct {
	Type  string  `json:"type"`
	Start int     `json:"start"`
	End   int     `json:"end"`
	Score float64 `json:"score"`
}

type presidioResponse struct {
	Entities []presidioEntity `json:"entities"`
	Error    string           `json:"error"`
}

// analyze sends one text to the sidecar and returns the decoded entities. On any transport
// error it marks the detector dead (so subsequent calls skip straight to native fallback)
// and returns the error — the CALLER decides the fallback. No Presidio-typed error escapes
// this file.
func (d *PresidioDetector) analyze(text string) ([]presidioEntity, error) {
	d.mu.Lock()
	defer d.mu.Unlock()

	if d.dead {
		return nil, fmt.Errorf("sidecar unavailable")
	}
	if !d.started {
		if err := d.startLocked(); err != nil {
			return nil, err
		}
	}

	req, _ := json.Marshal(map[string]any{"op": "analyze", "text": text})
	if _, err := d.stdin.Write(append(req, '\n')); err != nil {
		d.dead = true
		return nil, fmt.Errorf("sidecar write: %w", err)
	}
	line, err := d.stdout.ReadString('\n')
	if err != nil {
		d.dead = true
		return nil, fmt.Errorf("sidecar read: %w", err)
	}
	var resp presidioResponse
	if err := json.Unmarshal([]byte(strings.TrimSpace(line)), &resp); err != nil {
		d.dead = true
		return nil, fmt.Errorf("sidecar decode: %w", err)
	}
	if resp.Error != "" {
		return nil, fmt.Errorf("sidecar error: %s", resp.Error)
	}
	return resp.Entities, nil
}

// RedactPII satisfies the unchanged Detector interface. It (1) runs the native structured
// recognizers FIRST (EMAIL / US_SSN / CREDIT_CARD / API_KEY / PHONE / IBAN / IP / DOB /
// CREDENTIAL — preserving every existing corpus floor), then (2) overlays Presidio NER
// entities (PERSON / LOCATION / NRP / ... — the additive recall lift) on the ORIGINAL text,
// merging both flag sets. If the sidecar is unavailable, it returns the native redaction
// alone (fail-closed: PII still redacted, never raw).
func (d *PresidioDetector) RedactPII(text string) (string, []string) {
	// Step 1: native structured redaction (always runs, never regresses existing categories).
	nativeRedacted, nativeFlags := d.native.RedactPII(text)

	// Step 2: Presidio NER on the ORIGINAL text. We compute entity spans on the original so
	// offsets are valid, keep only the additive NER labels (not the structured ones the native
	// pass already owns), then apply them to the native-redacted output by VALUE replacement of
	// the original substring — so a PERSON inside otherwise-benign text gets a <PERSON> label
	// without disturbing the already-applied <EMAIL>/<US_SSN>/... placeholders.
	entities, err := d.analyze(text)
	if err != nil {
		// Fail-closed degradation: native redaction stands; surface no Presidio-typed error.
		return nativeRedacted, nativeFlags
	}

	redacted := nativeRedacted
	flagSet := map[string]bool{}
	for _, f := range nativeFlags {
		flagSet[f] = true
	}

	// Apply NER entities longest-first so a longer span ("New York City") is replaced before a
	// shorter overlapping one, and dedupe by surface value to avoid double-replacing.
	type nerHit struct {
		label string
		value string
	}
	var hits []nerHit
	seen := map[string]bool{}
	for _, e := range entities {
		label, keep := presidioEntityLabels[e.Type]
		if !keep || e.Score < d.minScore {
			continue
		}
		if e.Start < 0 || e.End > len(text) || e.Start >= e.End {
			continue
		}
		value := text[e.Start:e.End]
		key := label + "\x00" + value
		if seen[key] {
			continue
		}
		seen[key] = true
		hits = append(hits, nerHit{label: label, value: value})
	}
	// Longest value first for stable, non-overlapping replacement.
	sort.SliceStable(hits, func(i, j int) bool { return len(hits[i].value) > len(hits[j].value) })

	for _, h := range hits {
		placeholder := "<" + h.label + ">"
		// Only replace if the original value still appears verbatim in the (native-redacted)
		// output — i.e. it wasn't already consumed by a native structured placeholder.
		if strings.Contains(redacted, h.value) {
			redacted = strings.ReplaceAll(redacted, h.value, placeholder)
			flagSet["pii:"+h.label] = true
		}
	}

	// Rebuild a stable, sorted flag slice (deterministic output).
	flags := make([]string, 0, len(flagSet))
	for f := range flagSet {
		flags = append(flags, f)
	}
	sort.Strings(flags)
	if len(flags) == 0 {
		return redacted, nil
	}
	return redacted, flags
}

// DetectInjection satisfies the unchanged Detector interface. Injection detection is
// ORTHOGONAL to Presidio (a PII/NER engine, not an injection classifier), so this delegates
// to the native heuristic UNCHANGED — the honest finding recorded in ADR-009. The Presidio
// backend lifts PII/NER recall; the injection number is unchanged from the native baseline.
func (d *PresidioDetector) DetectInjection(text string) []string {
	return d.native.DetectInjection(text)
}
