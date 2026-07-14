// SPDX-License-Identifier: Apache-2.0
package main

// provenance_test.go: TC-001 through TC-008 for task 020 (write-provenance /
// source-class tagging).
//
// Every case asserts the EXACT value threaded, never merely "an event was emitted" or
// "a field exists". The load-bearing property: the stored entry and the emitted audit
// event agree, value-for-value, with the identity read at the ValidateWrite call site,
// and absent/garbage input degrades to the sentinel sourceClassUnknown rather than to a
// silent, more-trusted default.

import (
	"os"
	"path/filepath"
	"reflect"
	"regexp"
	"strings"
	"testing"
)

// ─── fixtures ─────────────────────────────────────────────────────────────────

var (
	idExternalTool = map[string]any{
		"spiffe_id":    "spiffe://secure-agents/agent/tool-runner",
		"trust_tier":   "attested",
		"source_class": "external_tool",
	}
	idAgentAuthored = map[string]any{
		"spiffe_id":    "spiffe://secure-agents/agent/planner",
		"trust_tier":   "attested",
		"source_class": "agent_authored",
	}
	idUserInput = map[string]any{
		"spiffe_id":    "spiffe://secure-agents/agent/operator-cli",
		"trust_tier":   "attested",
		"source_class": "user_input",
	}
	idNoSourceClass = map[string]any{
		"spiffe_id":  "spiffe://secure-agents/agent/alpha",
		"trust_tier": "attested",
	}
	idEmptySourceClass = map[string]any{
		"spiffe_id":    "spiffe://secure-agents/agent/alpha",
		"trust_tier":   "attested",
		"source_class": "",
	}
	idUnrecognizedSourceClass = map[string]any{
		"spiffe_id":    "spiffe://secure-agents/agent/alpha",
		"trust_tier":   "attested",
		"source_class": "tool_output", // plausible typo/legacy value, not in the enum
	}
)

// piiText reliably sets a pii:EMAIL flag without tripping injection detection.
const piiText = "contact alice@example.com about the rollout"

// findingForStoredID returns the finding whose StoredID matches want, so events are
// paired to writes by id rather than by fragile slice order. Injection-rejected events
// carry StoredID == "" (nothing persisted), so those are matched by index at the call
// site instead.
func findingForStoredID(events []OCSFEvent, want string) (OCSFFinding, bool) {
	for _, e := range events {
		if e.Finding.StoredID == want {
			return e.Finding, true
		}
	}
	return OCSFFinding{}, false
}

// ─── TC-001: contract shape is unchanged by the new optional key ──────────────

func TestProvenanceTC001_ContractShapeUnchanged(t *testing.T) {
	g := NewMemoryGuard(NewNativeDetector())

	res := g.ValidateWrite(piiText, idExternalTool)
	gotWriteKeys := keySet(res)
	wantWriteKeys := map[string]bool{"allow": true, "stored_id": true, "flags": true}
	if !reflect.DeepEqual(gotWriteKeys, wantWriteKeys) {
		t.Fatalf("validate_write response keys = %v, want exactly {allow, stored_id, flags} (no source_class leak)", keysOf(res))
	}
	if res["allow"] != true {
		t.Errorf("expected allow:true for a benign PII write, got %v", res["allow"])
	}
	storedID, _ := res["stored_id"].(string)
	if !regexp.MustCompile(`^mem-[0-9a-f]{12}$`).MatchString(storedID) {
		t.Errorf("stored_id %q does not match ^mem-[0-9a-f]{12}$", storedID)
	}

	rd := g.ValidateRead("contact", idExternalTool)
	gotReadKeys := keySet(rd)
	wantReadKeys := map[string]bool{"allow": true, "content_redacted": true, "flags": true}
	if !reflect.DeepEqual(gotReadKeys, wantReadKeys) {
		t.Fatalf("validate_read response keys = %v, want exactly {allow, content_redacted, flags} (read path untouched)", keysOf(rd))
	}
}

func keySet(m map[string]any) map[string]bool {
	out := make(map[string]bool, len(m))
	for k := range m {
		out[k] = true
	}
	return out
}

func keysOf(m map[string]any) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	return out
}

// ─── TC-002: sourceClassFromMap normalizes every input ────────────────────────

func TestSourceClassFromMapNormalization(t *testing.T) {
	cases := []struct {
		name     string
		identity map[string]any
		want     string
	}{
		{"external_tool", map[string]any{"source_class": "external_tool"}, sourceClassExternalTool},
		{"user_input", map[string]any{"source_class": "user_input"}, sourceClassUserInput},
		{"agent_authored", map[string]any{"source_class": "agent_authored"}, sourceClassAgentAuthored},
		{"system", map[string]any{"source_class": "system"}, sourceClassSystem},
		{"empty_map", map[string]any{}, sourceClassUnknown},
		{"empty_string", map[string]any{"source_class": ""}, sourceClassUnknown},
		{"unrecognized", map[string]any{"source_class": "tool_output"}, sourceClassUnknown},
		{"wrong_type_number", map[string]any{"source_class": 42}, sourceClassUnknown},
		{"nil_map", nil, sourceClassUnknown},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			got := sourceClassFromMap(c.identity)
			if got != c.want {
				t.Errorf("sourceClassFromMap(%v) = %q, want %q", c.identity, got, c.want)
			}
		})
	}
}

// TC-002 edge: source_class is NOT a fourth Principal accessor. The access-control
// seam stays exactly its three methods.
func TestSourceClassIsNotAPrincipalAccessor(t *testing.T) {
	pType := reflect.TypeOf((*Principal)(nil)).Elem()
	if n := pType.NumMethod(); n != 3 {
		var names []string
		for i := 0; i < n; i++ {
			names = append(names, pType.Method(i).Name)
		}
		t.Fatalf("Principal has %d methods %v, want exactly 3 (Subject, Attested, SharedScope); source_class must not be a 4th accessor", n, names)
	}
	for _, m := range []string{"Subject", "Attested", "SharedScope"} {
		if _, ok := pType.MethodByName(m); !ok {
			t.Errorf("Principal is missing expected method %q", m)
		}
	}
	if _, ok := pType.MethodByName("SourceClass"); ok {
		t.Error("Principal must NOT expose a SourceClass accessor; provenance is decoded standalone via sourceClassFromMap")
	}
}

// ─── TC-003: entry.sourceClass set from the same identity read as boundIdentity ─

func TestProvenanceTC003_EntrySetFromSameRead(t *testing.T) {
	store := NewInMemoryStore()
	g := NewMemoryGuard(NewNativeDetector(), store)

	res := g.ValidateWrite(piiText, idAgentAuthored)
	id, _ := res["stored_id"].(string)
	e, ok := store.Get(id)
	if !ok {
		t.Fatalf("stored entry %q not found", id)
	}
	if e.sourceClass != "agent_authored" {
		t.Errorf("entry.sourceClass = %q, want %q", e.sourceClass, "agent_authored")
	}
	if e.boundIdentity != "spiffe://secure-agents/agent/planner" {
		t.Errorf("entry.boundIdentity = %q, want %q (same idAgentAuthored read)", e.boundIdentity, "spiffe://secure-agents/agent/planner")
	}

	// A rejected (injection-suspected) write has no stored_id to read back (fail-closed),
	// but the provenance still reaches the audit event.
	sink := &CollectingSink{}
	gReject := NewMemoryGuard(NewNativeDetector()).WithAudit(AuditConfig{Enabled: true, Sink: sink})
	rej := gReject.ValidateWrite(injectionText, idExternalTool)
	if rej["allow"] != false || rej["stored_id"] != nil {
		t.Fatalf("expected fail-closed reject {allow:false, stored_id:nil}, got %v", rej)
	}
	events := sink.Events()
	if len(events) != 1 || events[0].Finding.Type != "injection_rejected" {
		t.Fatalf("expected one injection_rejected event, got %v", events)
	}
	if events[0].Finding.SourceClass != "external_tool" {
		t.Errorf("rejected-write event SourceClass = %q, want %q", events[0].Finding.SourceClass, "external_tool")
	}
}

// ─── TC-004: OCSFFinding.SourceClass populated on both write builders ─────────

func TestProvenanceTC004_BothBuildersPopulated(t *testing.T) {
	sink := &CollectingSink{}
	g := NewMemoryGuard(NewNativeDetector()).WithAudit(AuditConfig{Enabled: true, Sink: sink})

	g.ValidateWrite(piiText, idUserInput)           // BuildPIIRedactionEvent
	g.ValidateWrite(injectionText, idAgentAuthored) // BuildInjectionRejectedEvent

	events := sink.Events()
	if len(events) != 2 {
		t.Fatalf("expected 2 events, got %d: %v", len(events), events)
	}
	if events[0].Finding.Type != "pii_redaction" || events[0].Finding.SourceClass != "user_input" {
		t.Errorf("event[0] = {type:%q, source_class:%q}, want {pii_redaction, user_input}", events[0].Finding.Type, events[0].Finding.SourceClass)
	}
	if events[1].Finding.Type != "injection_rejected" || events[1].Finding.SourceClass != "agent_authored" {
		t.Errorf("event[1] = {type:%q, source_class:%q}, want {injection_rejected, agent_authored}", events[1].Finding.Type, events[1].Finding.SourceClass)
	}
}

// TC-004 edge: BuildDeletionEvent carries no writer-provenance field.
func TestProvenanceTC004_DeletionEventHasNoSourceClass(t *testing.T) {
	sink := &CollectingSink{}
	g := NewMemoryGuard(NewNativeDetector()).WithAudit(AuditConfig{Enabled: true, Sink: sink})
	res := g.ValidateWrite("meeting notes for Q3 planning", idAgentAuthored)
	id, _ := res["stored_id"].(string)
	g.VerifyDelete(id)

	events := sink.Events()
	var del *OCSFFinding
	for i := range events {
		if events[i].Finding.Operation == "verify_delete" {
			del = &events[i].Finding
		}
	}
	if del == nil {
		t.Fatal("no verify_delete event emitted")
	}
	if del.SourceClass != "" {
		t.Errorf("deletion event SourceClass = %q, want \"\" (deletion carries no writer provenance)", del.SourceClass)
	}
}

// ─── TC-005: external_tool vs agent_authored distinguishable end-to-end ───────
//
// This is the task's L5 validation harness (headline assertion). It exercises the real
// ValidateWrite → entry → audit-emission path, not a hand-set field.
func TestWriteProvenanceThreadsToEntryAndAuditEvent(t *testing.T) {
	store := NewInMemoryStore()
	sink := &CollectingSink{}
	g := NewMemoryGuard(NewNativeDetector(), store).WithAudit(AuditConfig{Enabled: true, Sink: sink})

	resA := g.ValidateWrite("contact alice@example.com about the rollout", idExternalTool)
	resB := g.ValidateWrite("contact bob@example.com about the launch", idAgentAuthored)
	idA, _ := resA["stored_id"].(string)
	idB, _ := resB["stored_id"].(string)

	eA, okA := store.Get(idA)
	eB, okB := store.Get(idB)
	if !okA || !okB {
		t.Fatalf("stored entries not found: A(%q)=%v B(%q)=%v", idA, okA, idB, okB)
	}

	// (a) stored entries distinguishable, value-for-value.
	if eA.sourceClass != "external_tool" {
		t.Errorf("entry A sourceClass = %q, want external_tool", eA.sourceClass)
	}
	if eB.sourceClass != "agent_authored" {
		t.Errorf("entry B sourceClass = %q, want agent_authored", eB.sourceClass)
	}
	if eA.sourceClass == eB.sourceClass {
		t.Errorf("entry A and B collapsed to the same sourceClass %q; provenance is not distinguished", eA.sourceClass)
	}

	// (b) emitted events distinguishable, paired to writes by stored_id (not slice order).
	fA, okfA := findingForStoredID(sink.Events(), idA)
	fB, okfB := findingForStoredID(sink.Events(), idB)
	if !okfA || !okfB {
		t.Fatalf("could not pair events to writes by stored_id: A=%v B=%v", okfA, okfB)
	}
	if fA.SourceClass != "external_tool" {
		t.Errorf("event for A SourceClass = %q, want external_tool", fA.SourceClass)
	}
	if fB.SourceClass != "agent_authored" {
		t.Errorf("event for B SourceClass = %q, want agent_authored", fB.SourceClass)
	}
	// stored entry and its event agree, value-for-value.
	if fA.SourceClass != eA.sourceClass || fB.SourceClass != eB.sourceClass {
		t.Errorf("event/entry provenance disagree: A(event=%q,entry=%q) B(event=%q,entry=%q)", fA.SourceClass, eA.sourceClass, fB.SourceClass, eB.sourceClass)
	}

	t.Logf("PROVENANCE end-to-end: entry A=%q event A=%q | entry B=%q event B=%q", eA.sourceClass, fA.SourceClass, eB.sourceClass, fB.SourceClass)
}

// ─── TC-006: absent/unrecognized never defaults to a more-trusted value ───────

func TestProvenanceTC006_UnknownDefault(t *testing.T) {
	store := NewInMemoryStore()
	sink := &CollectingSink{}
	g := NewMemoryGuard(NewNativeDetector(), store).WithAudit(AuditConfig{Enabled: true, Sink: sink})

	cases := []struct {
		text     string
		identity map[string]any
	}{
		{"contact alice@example.com about the rollout", idNoSourceClass},
		{"contact bob@example.com about the launch", idEmptySourceClass},
		{"contact carol@example.com about the merger", idUnrecognizedSourceClass},
	}
	for _, c := range cases {
		res := g.ValidateWrite(c.text, c.identity)
		id, _ := res["stored_id"].(string)
		e, ok := store.Get(id)
		if !ok {
			t.Fatalf("stored entry %q not found", id)
		}
		if e.sourceClass != sourceClassUnknown {
			t.Errorf("entry sourceClass = %q, want %q", e.sourceClass, sourceClassUnknown)
		}
		if e.sourceClass == "agent_authored" || e.sourceClass == "" {
			t.Errorf("entry sourceClass = %q must NOT default to agent_authored or \"\"", e.sourceClass)
		}
		f, okf := findingForStoredID(sink.Events(), id)
		if !okf {
			t.Fatalf("no event paired to stored_id %q", id)
		}
		if f.SourceClass != sourceClassUnknown {
			t.Errorf("event SourceClass = %q, want %q", f.SourceClass, sourceClassUnknown)
		}
		if f.SourceClass == "agent_authored" || f.SourceClass == "" {
			t.Errorf("event SourceClass = %q must NOT default to agent_authored or \"\"", f.SourceClass)
		}
	}
}

// TC-003/006 durability: sourceClass round-trips through FileStore across a restart, and a
// snapshot written without the field loads as "" (treated as unknown by consumers, ADR-015).
func TestProvenancePersistsAcrossFileStoreRestart(t *testing.T) {
	path := filepath.Join(t.TempDir(), "store.jsonl")
	s1, err := NewFileStore(path)
	if err != nil {
		t.Fatalf("NewFileStore: %v", err)
	}
	s1.Put("mem-1", entry{content: "planner memo", boundIdentity: "spiffe://x", sourceClass: sourceClassAgentAuthored})

	// Independent construction over the same path simulates a process restart.
	s2, err := NewFileStore(path)
	if err != nil {
		t.Fatalf("NewFileStore (restart): %v", err)
	}
	got, ok := s2.Get("mem-1")
	if !ok {
		t.Fatal("restarted FileStore did not see mem-1")
	}
	if got.sourceClass != sourceClassAgentAuthored {
		t.Errorf("sourceClass did not persist: got %q want %q", got.sourceClass, sourceClassAgentAuthored)
	}

	// A pre-provenance snapshot (no source_class key) loads with "" and no error.
	legacyPath := filepath.Join(t.TempDir(), "legacy.jsonl")
	if err := os.WriteFile(legacyPath, []byte(`{"id":"mem-9","content":"old","bound_identity":"","flags":[]}`+"\n"), 0o600); err != nil {
		t.Fatalf("write legacy snapshot: %v", err)
	}
	sLegacy, err := NewFileStore(legacyPath)
	if err != nil {
		t.Fatalf("NewFileStore(legacy): %v", err)
	}
	e, ok := sLegacy.Get("mem-9")
	if !ok {
		t.Fatal("legacy snapshot entry not loaded")
	}
	if e.sourceClass != "" {
		t.Errorf("legacy entry sourceClass = %q, want \"\" (treated as unknown)", e.sourceClass)
	}
}

// TC-006 edge: a nil identity (no map at all) also yields sourceClassUnknown.
func TestProvenanceTC006_NilIdentity(t *testing.T) {
	store := NewInMemoryStore()
	g := NewMemoryGuard(NewNativeDetector(), store)
	res := g.ValidateWrite("contact dana@example.com about the deal", nil)
	id, _ := res["stored_id"].(string)
	e, ok := store.Get(id)
	if !ok {
		t.Fatalf("stored entry %q not found", id)
	}
	if e.sourceClass != sourceClassUnknown {
		t.Errorf("nil-identity write sourceClass = %q, want %q", e.sourceClass, sourceClassUnknown)
	}
}

// ─── TC-008: producer→consumer single-decode fence ────────────────────────────
//
// Confirm source_class is decoded exactly once on the write path, so the stored entry
// and the emitted event can never drift from two independent reads. guard.go calls
// sourceClassFromMap(identity) exactly once and never reads identity["source_class"]
// directly; the only literal key lookup lives in principal.go's sourceClassFromMap.
func TestProvenanceTC008_SingleDecodeSite(t *testing.T) {
	guardSrc, err := os.ReadFile("guard.go")
	if err != nil {
		t.Fatalf("read guard.go: %v", err)
	}
	if n := strings.Count(string(guardSrc), "sourceClassFromMap("); n != 1 {
		t.Errorf("guard.go calls sourceClassFromMap %d times, want exactly 1 (single decode on the write path)", n)
	}
	if strings.Contains(string(guardSrc), `["source_class"]`) {
		t.Error(`guard.go reads identity["source_class"] directly; the only key lookup must be inside sourceClassFromMap (principal.go)`)
	}

	principalSrc, err := os.ReadFile("principal.go")
	if err != nil {
		t.Fatalf("read principal.go: %v", err)
	}
	if n := strings.Count(string(principalSrc), `identity["source_class"]`); n != 1 {
		t.Errorf(`principal.go reads identity["source_class"] %d times, want exactly 1 (inside sourceClassFromMap)`, n)
	}
}
