# Task 019: Size-anomaly detector (a second `WriteInspector` behind the task-018 seam)

**Project:** memory-guard
**Created:** 2026-07-14
**Status:** ❌ Not started

## Goal

Add `SizeAnomalyDetector`, a **stateful** detector that maintains a per-key rolling baseline of write sizes and flags a write whose size deviates beyond a configured threshold from that key's own recent history. It is the **second** implementation behind the `WriteInspector` seam task 018 introduces (task 018 ships the seam, its `WriteContext` argument, the guard wiring point, and its own first implementation, `SelfReinforcementDetector`; this task is purely "write a second implementation and let it run alongside the first," it does not touch the seam's shape). The statistical method is **stdlib-only** (rolling mean + standard deviation over a bounded window); findings surface as an **additive** flag (`size_anomaly_suspected`) on the existing `validate_write` `flags` array, with the tracer-validated `{allow, stored_id, flags}` contract shape **unchanged**. Because `MemoryGuard` wires exactly one `WriteInspector` at a time (task 018's `WithWriteInspector`), this task also adds a small fan-out composite so `SizeAnomalyDetector` can run **alongside** task 018's `SelfReinforcementDetector`, not only in its place.

## Context

- **Why size matters:** an unexpectedly large write relative to a key's normal pattern can signal exfil-prep (an agent staging a large blob for later retrieval) or a bulk poisoning payload (dumping many injected instructions in one write to raise the odds one survives detection). It is a **behavioral** signal: no single write is inherently suspicious out of context, only a write that is anomalous relative to that key's own history, which is exactly why it needs the task-018 seam rather than the existing content-only `Detector` seam (`detector.go`).
- **The `Detector` seam is stateless and stays that way.** `detector.go`'s `Detector` interface (`RedactPII`, `DetectInjection`) classifies one piece of text with no memory of prior calls; that is deliberate (ADR-001 §3, ADR-002) and this task does not add state to it. Task 018 introduces a **separate**, explicitly stateful seam for exactly this reason: content-only classification cannot see repetition or drift across writes.
- **The exact seam this task targets (per task 018's own test spec, `docs/tasks/test-specs/018-behavioral-detector-seam-self-reinforcement-test-spec.md`, TC-001/TC-008):** an interface named `WriteInspector` with one method, `Inspect(content string, ctx WriteContext) []string`, called once per **accepted** write (i.e. after the injection fail-closed check, so a rejected write neither trains nor trips a behavioral flag); a `MemoryGuard` builder method `WithWriteInspector(w WriteInspector) *MemoryGuard` mirroring `WithAudit`'s opt-in, nil-by-default pattern; and task 018's own implementation, `SelfReinforcementDetector`, which needs a per-subject key and (per its TC-005) a normalized source-class hint to route agent-authored repetition differently from human-authored repetition. That combination implies `WriteContext` carries at least the bound identity key and a normalized source-class string; this task assumes the shape below and **reconciles against task 018's actual ADR before coding** (018's own test spec hedges the same way: "the task's chosen equivalent signature, recorded in the ADR").
- **Note on 018's current state:** as of this task's authoring, only task 018's **test spec** exists in this repo (`docs/tasks/test-specs/018-behavioral-detector-seam-self-reinforcement-test-spec.md`); its task file (`docs/tasks/backlog/018-behavioral-detector-seam-self-reinforcement.md`) has not yet been written. This task cannot start until 018's task file exists, is executed, and merges to `main`. The Readiness gate below blocks on that explicitly.
- **The single-field wiring constraint:** `WithWriteInspector` takes one `WriteInspector` (task 018's TC-008(c) constructs a guard with **no** call to it as the disabled-by-default control, implying the field is singular, not a slice). Wiring `SizeAnomalyDetector` alongside `SelfReinforcementDetector` therefore needs a small fan-out type that itself satisfies `WriteInspector` and delegates to both, rather than a change to `MemoryGuard`'s wiring point (which is task 018's surface, out of scope to modify here).
- **Where it plugs into the write path:** `guard.go::ValidateWrite` computes `boundKey := boundKeyFor(principalFromMap(identity))` (ADR-004/ADR-013) before storing, and that is the same per-identity key this detector groups by (via `ctx.Key`, assumed name), so tenant isolation on the size baseline matches tenant isolation on reads (task 016). The detector observes `len(content)` where `content` is the argument `Inspect` receives, which per task 018's design is the post-PII-redaction text (the same bytes that get stored), not the raw pre-redaction input.
- **Additive-only flag contract:** `flags` on `validate_write` already carries `injection_suspected` and `pii:<LABEL>` entries (`docs/CONTRACT.md`), and will carry `self_reinforcement_suspected` once task 018 lands; this task adds one more possible string, `size_anomaly_suspected`, to the same array. No existing flag value, field name, or type changes. Task 016 and task 018 are the local precedent for "additive flag, unchanged contract shape"; the same discipline applies here.
- **Policy boundary: flags, does not block.** Unlike `injection_suspected` (fail-closed, ADR-001 §1), `size_anomaly_suspected` **flags only**; `allow` stays `true` and the write still persists when it is the only flag present, matching how task 018's `self_reinforcement_suspected` is designed. Whether a size anomaly should block, quarantine, or require review is a **policy-engine decision**, explicitly out of scope here and re-homed to task 022 (quarantine outcome) once that task exists. This task's only obligation is that the flag fires correctly and reaches the response array.

## Assumed `WriteInspector` seam shape (task 018, confirm before coding)

```go
// The following is this task's planning assumption, reconstructed from task 018's own test
// spec (018-behavioral-detector-seam-self-reinforcement-test-spec.md TC-001/TC-005/TC-008).
// Confirm against task 018's actual ADR and code before implementing REQ-001.

type WriteContext struct {
    Key         string // the bound identity key (boundKeyFor's result); per-subject grouping
    SourceClass string // normalized source_class (task 020); "unknown" if 020 has not landed yet
}

type WriteInspector interface {
    // Inspect observes one accepted write (post-redaction content, plus its write context) and
    // returns zero or more additional flags to append to validate_write's flags array.
    // Implementations own their own state; Inspect is called once per accepted
    // (non-injection-rejected) write.
    Inspect(content string, ctx WriteContext) []string
}
```

## Requirements

| Req ID | Description | Priority |
|--------|-------------|----------|
| REQ-001 | New `SizeAnomalyDetector` (`detector_size.go`) satisfies the `WriteInspector` seam: `Inspect(content string, ctx WriteContext) []string`, sizing on `len(content)`. It maintains, per `ctx.Key`, a **bounded ring buffer** of the `WindowSize` most recent write sizes (bytes). On each `Inspect` call the detector computes the mean and population standard deviation over the **existing** buffer for that key (before the current sample is added, so an anomalous sample never dilutes the baseline it is compared against), applies the anomaly test, **then** appends `size` to the key's buffer (evicting the oldest sample once at `WindowSize` capacity). | must have |
| REQ-002 | Configurable via a `SizeAnomalyConfig{WindowSize int, SigmaThreshold float64, MinSamples int}` struct passed to `NewSizeAnomalyDetector(cfg SizeAnomalyConfig)`. Documented defaults: `WindowSize=20`, `SigmaThreshold=3.0`, `MinSamples=5`. A zero-value `SizeAnomalyConfig{}` resolves to these defaults (never a divide-by-zero or always-flagging config). | must have |
| REQ-003 | Anomaly test: flags `size_anomaly_suspected` iff `ctx.Key`'s buffer already holds **at least `MinSamples`** samples **and** `abs(size - mean) > SigmaThreshold * stddev`. Zero-variance edge case: when `stddev == 0` (every prior sample identical), any `size != mean` flags (there is no "within N sigma" of a single repeated value) and `size == mean` does not. | must have |
| REQ-004 | Cold-start safety: for any key, the first `MinSamples - 1` `Inspect` calls **never** flag, regardless of how much their sizes vary from each other. The buffer is still being seeded, not yet a baseline. | must have |
| REQ-005 | Per-key isolation: each `ctx.Key`'s ring buffer and running statistics are **fully independent**. Writes under key A never affect key B's baseline (including the reserved `sharedScopeKey` and `unboundKey` markers, which each get their own independent baseline like any other key). `ctx.SourceClass` is **not** consulted by this detector (size anomaly is orthogonal to provenance in this task's scope; see Out of scope). | must have |
| REQ-006 | Findings surface **only** through the existing `flags` array on `validate_write`: a size anomaly appends `"size_anomaly_suspected"` to the same slice `piiFlags`/`injection_suspected`/(once 018 lands) `self_reinforcement_suspected` populate today; `allow` and `stored_id` are **unaffected** by this flag. A write flagged `size_anomaly_suspected` (and nothing else) still returns `allow:true` and a real `stored_id`, and still persists. The `{allow, stored_id, flags}` shape is byte-for-byte unchanged (no new top-level field). | must have |
| REQ-007 | A small fan-out composite (e.g. `CombineInspectors(inspectors ...WriteInspector) WriteInspector`) that itself satisfies `WriteInspector`: `Inspect` calls each wrapped inspector in order and returns the **union** (deduplicated, order-stable) of every flag any of them returned. This lets an operator wire `guard.WithWriteInspector(CombineInspectors(selfReinforcementDetector, sizeAnomalyDetector))` and get both detectors' findings without `MemoryGuard` gaining a second field. Combining must not change either wrapped detector's own per-call behavior or state (each still sees every accepted write exactly once, in the same order it would alone). | must have |
| REQ-008 | `MemoryGuard` wiring: the detector (directly, or composed via REQ-007) is wired through task 018's `WithWriteInspector` (an explicit opt-in, nil/disabled by default), so a guard constructed without opting in behaves identically to pre-019 (no `size_anomaly_suspected` ever appears, no per-key state is retained). The live CLI/`serve` construction path (whatever config factory task 018 adds in `main.go`) is confirmed reachable for `SizeAnomalyDetector`, mirroring task 018's own TC-008 live-path check. | must have |
| REQ-009 | `SizeAnomalyDetector` is **safe for concurrent use** (its own internal locking around the per-key buffer map). It is a second stateful detector in the tree (after task 018's `SelfReinforcementDetector`) and must not rely on the caller's lock scope for correctness. `CombineInspectors`' composite adds no shared mutable state of its own (an immutable slice of wrapped inspectors), so it needs no additional locking beyond what each wrapped inspector already provides. | must have |
| REQ-010 | **Stdlib-only.** Mean/standard-deviation computation uses only `math` (and slices/maps) from the standard library, no statistics package, no new module. `go.mod` stays require-free. | must have |
| REQ-011 | Spec propagation in the same commit: `docs/spec/interfaces.md` (the new flag value, `SizeAnomalyDetector` as a second entry under the `WriteInspector` "Extension points" listing task 018 establishes, and `CombineInspectors`), `docs/spec/behaviors.md` (the flag-only, non-blocking behavior and the policy-engine/task-022 boundary), `docs/spec/data-model.md` (the per-key size-baseline state), `docs/spec/configuration.md` (the three config knobs and their defaults). A new ADR (number assigned at execution time) records the statistical method, the compare-then-update ordering (REQ-001), the zero-variance edge case (REQ-003), the fan-out composite decision (REQ-007), and the explicit policy-engine boundary. | must have |

## Readiness gate

- [ ] Test spec `019-size-anomaly-detector-test-spec.md` exists in `docs/tasks/test-specs/`
- [ ] **Task 018 merged.** As of this task's authoring, only task 018's test spec exists in this repo; its task file must first be written, executed, and merged to `main` (with the real `WriteInspector`/`WriteContext` shape and `WithWriteInspector` wiring point) before this task can start
- [ ] The assumed `WriteContext`/`WriteInspector` shape above reconciled against task 018's actual shipped interface; any delta recorded in this task's ADR before code is written
- [ ] Confirm the next free ADR number against `docs/architecture/decisions/` at execution time
- [ ] Verification plan below filled in before any code (per `AGENTS.md` "Always")

## Acceptance criteria

- [ ] [REQ-001] Compare-then-update ordering holds: the anomaly test for sample N runs against a baseline built from samples 1..N-1 only, never including N itself (TC-001).
- [ ] [REQ-002] Default config resolves from a zero-value struct; explicit config overrides each field independently (TC-002).
- [ ] [REQ-003] Sigma-threshold flagging fires exactly at the documented boundary condition, and the zero-variance edge case behaves as specified (TC-003).
- [ ] [REQ-004] The first `MinSamples - 1` writes for a fresh key never flag, even with wildly different sizes (TC-004).
- [ ] [REQ-005] Two keys with divergent size patterns never cross-contaminate each other's baseline or flags, and `ctx.SourceClass` has no effect on the outcome (TC-005).
- [ ] [REQ-006] `validate_write`'s response shape is unchanged; a size-anomaly-only write still returns `allow:true` with a real `stored_id`, and the flag is additive alongside PII/injection flags when more than one condition fires on the same write (TC-006).
- [ ] [REQ-007] `CombineInspectors` fans a single accepted write out to every wrapped inspector, unions their flags, and leaves each wrapped inspector's own state exactly as it would be if called alone (TC-007).
- [ ] [REQ-008] With the detector not opted in, guard behavior (including the flags array) is byte-for-byte identical to pre-019; opted in (directly or via `CombineInspectors`), `Inspect` is keyed by the same `boundKeyFor` value that gates storage/read isolation, reachable from the live `serve`/`write` construction path (TC-008).
- [ ] [REQ-009] Concurrent `Inspect` calls across goroutines (`go test -race`) show no data race and no lost updates to the per-key buffer, including through `CombineInspectors` (TC-009).
- [ ] [REQ-010] `go.mod` has no `require` block; `detector_size.go` imports only stdlib packages (TC-010).
- [ ] [REQ-011] ADR plus the four listed spec files updated in the same commit; no future-tense statements land in `docs/spec/` (TC-011).
- [ ] `go build ./... && go test ./...` green; `go test -race ./...` green; existing suites (poisoning, PII corpus, identity isolation, audit, and task 018's self-reinforcement suite) unaffected.

## Verification plan

- **Highest level achievable: L5.** A validation-harness test establishes a baseline of roughly 20 normal-sized writes for one key through the live `ValidateWrite` path (opted into the detector via `WithWriteInspector`), then submits one outsized write and asserts `flags` contains `size_anomaly_suspected` while `allow:true` and `stored_id` is non-nil; a control write of normal size in the same run asserts the flag is **absent**; the first `MinSamples-1` writes in a fresh run assert the flag never fires regardless of size spread. A second run wires `CombineInspectors(sizeAnomalyDetector, aNoOpOrSpySecondInspector)` and confirms both detectors' flags appear together on a write that trips both. Record the final assertion lines (pass/fail per case) in the verify commit. **L6 (optional):** a live `serve` session: write roughly 20 similarly-sized entries under one identity via `nc -U`, then one large outlier, quoting the JSON response showing `size_anomaly_suspected` in `flags`.
- **Level 2 (unit):** `go test -run TestSizeAnomaly -count=1 ./...` returns `ok`, covering TC-001 through TC-010 individually (compare-then-update ordering, config defaults, sigma boundary plus zero-variance edge, cold-start, per-key isolation, contract-shape/allow-unaffected, fan-out composite, seam wiring/disabled-by-default, concurrency).
- **Level 2b (race):** `go test -race -run TestSizeAnomalyConcurrent ./...` returns `ok`, no `WARNING: DATA RACE`.
- **Level 3 (gate):** `go build ./... && go test ./...` exits 0; `go.mod` diff shows no `require` block added.
- **Level 5 (validation harness):** the baseline-then-outlier-then-control sequence above, run through the real `ValidateWrite` (not a hand-constructed detector call), is the recorded L5 evidence. It proves the detector is reachable on the live write path, not merely unit-correct in isolation.

## Out of scope

- The `WriteInspector` seam itself, `WriteContext`, the `WithWriteInspector` wiring point, and task 018's own `SelfReinforcementDetector`: task 018's responsibility, not rebuilt or modified here.
- Any policy decision about what happens when `size_anomaly_suspected` fires (block, quarantine, require human review): re-homed to task 022 (quarantine outcome); this task only flags.
- Using `ctx.SourceClass` (task 020) to vary size-anomaly sensitivity by provenance (e.g. a looser threshold for `system` writes): a plausible future refinement, not this task's scope. This task treats every source class identically.
- Cross-key or global anomaly detection (e.g. "this write is large relative to the whole store, not just this key's history"): a different statistical question, not this task's per-key scope.
- Adaptive-baseline poisoning resistance (an attacker slowly ramping write sizes to drag the rolling mean upward and normalize an eventually-large payload): a known limitation of any rolling-baseline detector, documented in the ADR as a follow-up concern, not solved here.
- Persisting the per-key size baseline across a process restart: the baseline is in-memory only, matching the current `InMemoryStore`/`TwoIndexStore` default; durability parity with task 016's identity work is a separate future task if ever needed.
- Modifying `MemoryGuard` to hold multiple `WriteInspector` fields directly: the `CombineInspectors` composite (REQ-007) solves the multi-detector need without touching task 018's wiring surface.

## Dependencies

- **Depends on:** task 018 (the `WriteInspector` seam, `WriteContext`, `WithWriteInspector`, `SelfReinforcementDetector`). Cannot start until 018's task file exists, is executed, and merges to `main`.
- **Soft-depends on:** task 020 (`source_class` tagging) only insofar as `ctx.SourceClass` may be `"unknown"` if 020 has not landed by the time 019 runs; this task does not require 020 to be functionally correct, since it never reads `ctx.SourceClass`.
- **Blocks:** nothing in the current backlog directly; a future task 022 (quarantine outcome) would consume the `size_anomaly_suspected` flag this task produces.
- **Independent of:** task 017 (audit emission). No shared files beyond `guard.go`'s existing optional-seam wiring pattern, safe to sequence either way after 018.
