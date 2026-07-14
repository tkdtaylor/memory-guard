# ADR-016: Behavioral-detector seam (`WriteInspector`) + `SelfReinforcementDetector`

**Status:** Accepted
**Date:** 2026-07-14
**Task:** [018 (Behavioral-detector seam + `SelfReinforcementDetector`)](../../tasks/completed/018-behavioral-detector-seam-self-reinforcement.md)
**Relates to:** ADR-002 (the `Detector` seam this one sits beside, unchanged), ADR-005 (the `MemoryStore` seam, the precedent for a second stateful seam rather than folding state into `Detector`), ADR-007 (the `AuditSink` seam wired via an immutable `WithAudit` builder, the pattern `WithWriteInspector` copies), ADR-008 (the tracer-validated `validate_write` response shape this ADR leaves byte-identical), ADR-015 (the `source_class` write-provenance tag whose signal this detector consumes).

## Context

`Detector` (`detector.go`) is a pure function of a single text: `RedactPII(text)` and `DetectInjection(text)`. It cannot see prior writes, so it structurally cannot detect an agent poisoning itself through repetitive self-authored writes. That failure mode (ASI06-adjacent) is behavioral: an agent's own prior writes get echoed or paraphrased back into new writes, amplifying an error or an injected belief through repetition rather than through a single injected payload (which the existing `injection_suspected` path already covers). The signal is a repetition pattern over time, not a lexical property of any one write.

Bolting write-history state onto `Detector` would break the "pure function of one text" property every `Detector` implementation (`RegexDetector`, `NativeDetector`, `PresidioDetector`) relies on, and would force every backend swap to also carry write-history plumbing it does not need.

## Decision

**Introduce a second, stateful detection seam, `WriteInspector`, distinct from `Detector`, ship its first implementation `SelfReinforcementDetector`, and wire it into `MemoryGuard` via an opt-in `WithWriteInspector` builder that mirrors `WithAudit`. Findings surface as an additive `self_reinforcement_suspected` value on the existing `validate_write` `flags` array; the tracer-validated `{allow, stored_id, flags}` shape is unchanged, and the flag is non-blocking (fail-open).**

### 1. A second seam, not an extension of `Detector`

```go
type WriteContext struct {
    Key         string // the writer's normalized identity key (boundKeyFor)
    SourceClass string // the write's raw source-class provenance hint
}

type WriteInspector interface {
    Inspect(content string, ctx WriteContext) []string
}
```

`Detector` (`detector.go`) stays byte-for-byte unchanged: same method set (`RedactPII`, `DetectInjection`), same signatures, same doc comments. `WriteInspector` is a separate interface in `write_inspector.go`. This is the fourth seam in the block, alongside `Detector` (ADR-002), `MemoryStore` (ADR-005), and `AuditSink` (ADR-007), and follows the established discipline: the concrete implementation lives behind the interface, and `guard.go` holds only the interface type. Unlike `Detector`, a `WriteInspector` is explicitly permitted to hold state (a bounded per-identity write history), because that state is the entire point of cross-write detection. The state lives inside the seam implementation, not in `guard.go` or the `MemoryStore` (it is detection-internal working state, not persisted agent memory content).

**Rejected alternative: add a `DetectRepetition(text, history)` method to `Detector`.** Rejected because it forces every `Detector` backend (including a future Presidio one) to carry history plumbing it does not use, and collapses two independently swappable concerns (stateless single-text detection vs. stateful cross-write behavioral detection) into one interface.

### 2. `SelfReinforcementDetector`: token-set overlap, cooldown-bounded history

`SelfReinforcementDetector` flags `self_reinforcement_suspected` when an incoming write's token-set similarity to `max_self_writes` or more prior same-subject writes inside the `cooldown` window each meets or exceeds `similarity_threshold`. All three parameters are constructor-configurable (functional options), plus an injectable `clock func() time.Time` so cooldown-window tests are deterministic without real sleeps.

**Default wiring values (`main.go` `serve` / `write` path):** `similarity_threshold = 0.85`, `cooldown = 5 * time.Minute`, `max_self_writes = 3`. These are the values `NewSelfReinforcementDetector()` ships with; tests override them via options (the test spec drives `0.75 / 10m / 3`).

**Similarity method: the token-set overlap coefficient (Szymkiewicz–Simpson), `|A ∩ B| / min(|A|, |B|)`, stdlib-only.** Tokens are lowercased alphanumeric runs (`regexp` + `map[string]struct{}`); no vector database, no embedding/ML model, no third-party dependency, `go.mod` stays require-free. The task and test spec loosely call this "token-set / Jaccard overlap"; the *symmetric* Jaccard index (`|A ∩ B| / |A ∪ B|`) does **not** satisfy the test corpus's asserted `≥ 0.75` pairwise figures (e.g. the paraphrase pair `rep4`/`rep2` measures `4/9 ≈ 0.44` under symmetric Jaccard), whereas the overlap coefficient measures `4/5 = 0.80` and every `rep`-pair lands `≥ 0.75`. The overlap coefficient is the set-based method consistent with the fixtures, so it is the one shipped. Empty token sets score `0` (no divide-by-zero, no spurious match).

**Bounded memory:** per-subject history is evicted two ways: (a) records older than `cooldown` relative to the current write are pruned on every `Inspect`, and (b) a hard per-subject size cap (`maxHistoryPerSubject = 256`) trims the oldest records so a single identity's history can never grow without bound. A test-visible `historySize(key)` accessor asserts the cap holds across many writes spanning several windows.

### 3. Flag semantics and the policy boundary: this task flags, it does not block

`self_reinforcement_suspected` is **additive** on the existing `flags []string` and **non-blocking**: a write carrying it is still `allow:true` with a non-nil `stored_id`. This is a deliberate policy boundary. The write-gate's existing fail-closed invariant (a `injection_suspected` write is rejected, `allow:false`, `stored_id:null`, nothing persists) is untouched: the behavioral inspection runs only on the accepted path, after the injection gate, and never changes a verdict. Whether `self_reinforcement_suspected` should ever become blocking, quarantined, or routed to human review is a policy-engine decision, expected to be picked up by a future quarantine-outcome task (referenced in planning as task 022). This task computes the signal honestly, surfaces it as a flag, and stores the write exactly as it would have without the task.

### 4. Source-class routing (REQ-007) and the task-020 integration actually taken

The detector scrutinizes a write only when it is treated as agent-authored. The routing is binary: the single explicit non-agent class `human_authored` suppresses detection (human repetition is out of scope for self-reinforcement); every other value, including an absent hint, an empty string, and any unrecognized value, defaults to agent-authored (fail-closed toward scrutiny, consistent with this project's posture and with ADR-015's instruction that `sourceClassUnknown` be treated at least as cautiously as an untrusted class).

**Task-020 integration, path taken.** The pinned decision was to reuse task 020's `sourceClassFromMap(identity)` and treat its `agent_authored` value as the agent-authored branch. On execution, `sourceClassFromMap` was found present in `principal.go` but its recognized vocabulary is `{external_tool, user_input, agent_authored, system}` and it normalizes everything else to `sourceClassUnknown`. The test spec's REQ-007 model uses `{agent_authored, human_authored, absent}` and requires `human_authored` to never flag while an absent hint defaults to agent-authored and *does* flag. `sourceClassFromMap` collapses `human_authored` and the absent case to the same `unknown` value, so it cannot express the three-way routing REQ-007 / TC-005 demand: reusing it verbatim would fail either TC-005a (human never flags) or TC-005b (absent defaults to agent-authored). Therefore the behavioral seam reads a raw provenance hint via a new sibling helper `writeProvenanceHint(identity)` (the trimmed raw `source_class` string, absent → `""`), and `SelfReinforcementDetector` interprets `!= "human_authored"` as agent-authored. `sourceClassFromMap` remains untouched and continues to decode the stored entry's provenance and the audit event's provenance (ADR-015). When task 020's wire shape settles, 018 needs no rework: an explicit `human_authored` opts a write out, everything else stays scrutinized.

### 5. Opt-in builder, default-off, behavior-preserving

`MemoryGuard` gains `WithWriteInspector(wi WriteInspector) *MemoryGuard`, an immutable builder mirroring `WithAudit`: it returns a modified copy, defaults to nil (seam off), and leaves every pre-existing `NewMemoryGuard(det)` / `NewMemoryGuard(det, store)` call site compiling and behaving byte-for-byte unchanged. A guard built without the call can never emit `self_reinforcement_suspected`. `main.go` wires a live `SelfReinforcementDetector` into the `serve` and `write` construction paths by default, with a documented off-switch: `MEMGUARD_SELF_REINFORCEMENT=off` disables the seam (any other value, including unset, leaves it on). The seam is therefore provably live on the CLI path, not merely unit-tested.

### 6. Seam isolation

No `SelfReinforcementDetector`-specific token (its type name, its similarity helper, its history struct) appears in `guard.go`, `ipc.go`, or `docs/CONTRACT.md`. `guard.go` holds only the `WriteInspector` interface and constructs a `WriteContext` at the single behavioral-seam call site inside `ValidateWrite`, exactly as it holds `Detector` and `MemoryStore` at their call sites. The single wiring call site for the concrete detector is `main.go`'s `buildWriteInspector`. `docs/CONTRACT.md` and `detector.go` are byte-for-byte unchanged: the additive flag needs no contract edit, since `flags []string` already admits new string values.

## Consequences

### Known audit-emission gap (deliberately out of scope)

`guard.go::ValidateWrite` emits an audit-trail event only when `len(piiFlags) > 0`. A write flagged `self_reinforcement_suspected` with no PII present therefore emits **no** audit-trail event under today's emission gate. This task does not change that gate and does not add a dedicated `BuildSelfReinforcementEvent` builder or broaden the emission condition. The gap is recorded here as a known, deliberate limitation. Wiring a dedicated emission path for the behavioral flag is a follow-up (it would decide the event class, severity, and whether the flag alone warrants an event), left for the quarantine-outcome task or a dedicated emission task.

### Other consequences

- The block now has a second, independently swappable detection seam. A richer behavioral detector (semantic/embedding similarity, cross-identity correlation) slots in behind `WriteInspector` with zero guard/IPC/contract impact.
- `writeProvenanceHint` is a second read of `source_class` on the write path (alongside `sourceClassFromMap`). Both read the same immutable identity-map key for different concerns (behavioral hint vs. stored/audited provenance), so they cannot drift; the duplication is documented at the call site.
- Cross-identity or cross-tenant self-reinforcement correlation, and bounding the *number of distinct tracked identities* (a memory-exhaustion hardening concern distinct from bounding one identity's history), are noted follow-ups, not addressed here.
