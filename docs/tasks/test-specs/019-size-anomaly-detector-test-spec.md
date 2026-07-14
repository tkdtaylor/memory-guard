# Test Spec 019: Size-anomaly detector (second `WriteInspector` implementation)

**Linked task:** [`docs/tasks/backlog/019-size-anomaly-detector.md`](../backlog/019-size-anomaly-detector.md)
**Written:** 2026-07-14

> Authored ahead of execution and ahead of task 018's task file existing (only 018's test spec is present at the time of writing). Every case below targets `SizeAnomalyDetector` directly (unit-level, exercising `Inspect` in isolation) or through `MemoryGuard.ValidateWrite` (integration-level, exercising the real write path). If task 018 ships a `WriteInspector`/`WriteContext` shape different from `Inspect(content string, ctx WriteContext) []string` with `WriteContext{Key, SourceClass}` as assumed here, translate the calls below mechanically; the assertions and expected values do not change. Set-equality and real-value assertions throughout, never a "the call did not panic" smoke check.

## Requirements coverage

| Req ID | Test cases | Locally verifiable? | Covered? |
|--------|-----------|---------------------|----------|
| REQ-001 | TC-001 | ✅ | ✅ |
| REQ-002 | TC-002 | ✅ | ✅ |
| REQ-003 | TC-003 | ✅ | ✅ |
| REQ-004 | TC-004 | ✅ | ✅ |
| REQ-005 | TC-005 | ✅ | ✅ |
| REQ-006 | TC-006 | ✅ | ✅ |
| REQ-007 | TC-007 | ✅ | ✅ |
| REQ-008 | TC-008 | ✅ | ✅ |
| REQ-009 | TC-009 | ✅ | ✅ |
| REQ-010 | TC-010 | ✅ | ✅ |
| REQ-011 | TC-011 | ✅ | ✅ |

## Pre-implementation checklist

- [ ] All test cases below are defined
- [ ] Expected inputs and outputs are specified for each case
- [ ] Edge cases and error paths are covered
- [ ] Every REQ-ID from the task has at least one test case
- [ ] Task 018's actual `WriteInspector`/`WriteContext` shape confirmed and any delta from the assumed `Inspect(content string, ctx WriteContext) []string` / `WriteContext{Key, SourceClass}` signature reconciled before these cases are implemented
- [ ] The full pre-existing suite (poisoning, PII corpus, identity isolation, audit, and task 018's self-reinforcement suite) passes unchanged with `SizeAnomalyDetector` not opted in

## Test fixtures

- **Config under test:** `cfg := SizeAnomalyConfig{WindowSize: 5, SigmaThreshold: 3.0, MinSamples: 5}` for the fast-converging unit cases (small window keeps test data short); a second fixture `defaultCfg := SizeAnomalyConfig{}` to prove the documented defaults (`WindowSize=20, SigmaThreshold=3.0, MinSamples=5`) resolve correctly.
- **Write contexts:** `ctxA := WriteContext{Key: "spiffe://secure-agents/agent/alpha", SourceClass: "agent_authored"}`, `ctxB := WriteContext{Key: "spiffe://secure-agents/agent/beta", SourceClass: "agent_authored"}`, `ctxAOtherSource := WriteContext{Key: "spiffe://secure-agents/agent/alpha", SourceClass: "external_tool"}` (same key, different source class, used only in TC-005 to prove source class is ignored), `ctxShared := WriteContext{Key: sharedScopeKey}`, `ctxUnbound := WriteContext{Key: unboundKey}` (the reserved markers from `principal.go`, reused here as ordinary keys).
- **Size sequences (bytes), keyed to `cfg` above (`WindowSize=5, MinSamples=5`):**
  - `steadySeq = [100, 102, 98, 101, 99]` (mean ≈ 100, stddev ≈ 1.41): five samples, low variance, the baseline for the sigma-boundary cases.
  - `outlier = 500` (a value clearly beyond `100 + 3*1.41 ≈ 104.2`): the size submitted as the sixth call to trip the anomaly test.
  - `nearBoundary = 104` and `farBoundary = 105`: probe values straddling the `3.0`-sigma cutoff against the `steadySeq` baseline (`mean=100, stddev≈1.4142`, cutoff `≈104.24`); `104` (`\|104-100\|/1.4142 ≈ 2.83σ`) must NOT flag, `105` (`\|105-100\|/1.4142 ≈ 3.54σ`) must flag.
  - `identicalSeq = [200, 200, 200, 200, 200]`: the zero-variance fixture (stddev = 0 after 5 samples).
- **Content strings for guard-level fixtures:** benign filler text sized to hit specific byte counts after PII redaction is applied unchanged (e.g. `strings.Repeat("x", n)` padding around a fixed prefix), so the test can target exact `len(content)` values without PII interference.
- **Guard-level fixtures:** a `MemoryGuard` built with `NewMemoryGuard(NewNativeDetector())` and opted into a `SizeAnomalyDetector(cfg)` via `g.WithWriteInspector(NewSizeAnomalyDetector(cfg))`; a second guard built **without** opting in, for the disabled-by-default comparison in TC-008; a third guard opted into `CombineInspectors(sizeDet, spySecondInspector)` for TC-007.
- **Spy `WriteInspector`:** a test-local counting wrapper letting the test force its return value, mirroring task 018's own dead-wire mutation-probe pattern, used in TC-007 and TC-008.

## Test cases

### TC-001: compare-then-update ordering (baseline excludes the current sample)
- **Requirement:** REQ-001
- **Input:** `d := NewSizeAnomalyDetector(cfg)` (`cfg` as above, `WindowSize=5, MinSamples=5`). Call `d.Inspect(text(s), ctxA)` once for each size `s` in `steadySeq`, using a content string whose length is exactly `s` (five calls, all non-flagging per TC-004's cold-start rule for the first four, and the fifth checked against the first four only). Then call `d.Inspect(text(outlier), ctxA)` (the sixth call).
- **Expected:** the sixth call's flags are `["size_anomaly_suspected"]`, and the check that produced it was evaluated against `mean≈100, stddev≈1.41` (the five `steadySeq` values, not `outlier` itself). **Regression check:** call `d.Inspect(text(outlier), ctxA)` a **second time** immediately after; it must ALSO flag. If the implementation had folded `outlier` into the buffer before computing stats for the same call, the buffer's window would already contain `500` by the second call, shifting the mean upward enough that a second identical outlier could fail to flag; asserting it flags twice in a row proves each call's test uses the pre-update buffer.
- **Edge cases:** confirm via a buffer-inspection helper (or exported test-only accessor) that after the sixth call the buffer for `ctxA.Key` holds exactly `[102, 98, 101, 99, 500]` (oldest `100` evicted at `WindowSize=5` capacity, `500` appended after the test ran).

### TC-002: config defaults and overrides
- **Requirement:** REQ-002
- **Input:** `d1 := NewSizeAnomalyDetector(SizeAnomalyConfig{})` (zero value); `d2 := NewSizeAnomalyDetector(SizeAnomalyConfig{WindowSize: 10})` (partial override); `d3 := NewSizeAnomalyDetector(SizeAnomalyConfig{WindowSize: 10, SigmaThreshold: 2.0, MinSamples: 3})` (full override).
- **Expected:** `d1`'s effective config is `WindowSize=20, SigmaThreshold=3.0, MinSamples=5` (verified behaviorally: submitting fewer than 5 samples never flags regardless of spread, matching TC-004's method, and the 20th/21st call demonstrates the window boundary). `d2`'s `SigmaThreshold` and `MinSamples` fall back to defaults (`3.0`, `5`) while `WindowSize` is `10` (verified by observing eviction after the 11th call). `d3` uses all three overridden values (verified by observing a flag at `MinSamples=3` samples with `SigmaThreshold=2.0` against a low-variance sequence that a `3.0`-sigma config would NOT have flagged).
- **Edge cases:** a config with `MinSamples: 0` or `WindowSize: 0` must not divide-by-zero or panic; the detector treats it as "use the default" (documented fallback), asserted by a direct call that would otherwise panic on an empty buffer.

### TC-003: sigma-threshold boundary and the zero-variance edge case
- **Requirement:** REQ-003
- **Input:** seed a fresh detector with `steadySeq` under `ctxA` (five `Inspect` calls, `cfg` as in fixtures). Call `d.Inspect(text(nearBoundary), ctxA)` on a **cloned** detector state (re-seed `steadySeq` fresh, since TC-001 already consumed one instance), then separately re-seed and call `d.Inspect(text(farBoundary), ctxA)`. Separately, seed a fresh detector with `identicalSeq` (`[200]*5`) under `ctxB`, then call `d.Inspect(text(200), ctxB)` and, on a fresh re-seed, `d.Inspect(text(201), ctxB)`.
- **Expected:** `nearBoundary` (104, ≈2.83σ) returns `nil` (no flag); `farBoundary` (105, ≈3.54σ) returns `["size_anomaly_suspected"]`. On the zero-variance fixture: `Inspect(text(200), ctxB)` (exactly the repeated value) returns `nil`; `Inspect(text(201), ctxB)` (any deviation from a zero-stddev baseline) returns `["size_anomaly_suspected"]`.
- **Edge cases:** the comparison uses strict `>`, not `>=`, on `abs(size-mean) > SigmaThreshold*stddev`, so a value landing exactly on the computed cutoff (constructed with a synthetic sequence where the arithmetic works out exact, e.g. `mean=100, stddev=2, SigmaThreshold=3` giving cutoff `106`) does **not** flag at `106` but does flag at integer `107`.

### TC-004: cold-start never flags before `MinSamples`
- **Requirement:** REQ-004
- **Input:** fresh detector, `cfg.MinSamples=5`. Call `d.Inspect(text(s), ctxA)` for `s` in `[1, 100000, 5, 999999]` (four wildly divergent sizes, one call each, same key).
- **Expected:** all four calls return `nil` (no flag), regardless of the huge spread, because the buffer has fewer than `MinSamples` prior samples at each call.
- **Edge cases:** the fifth call (`d.Inspect(text(50000), ctxA)`, still wildly different) is now evaluated against the four seeded samples (`mean=25026, stddev` computed from `[1,100000,5,999999]`); assert only that flagging becomes *possible* from the fifth call onward, not a specific outcome on this particular adversarial sequence (the boundary math is covered precisely by TC-003; this case is purely about the `MinSamples` gate).

### TC-005: per-key isolation, reserved marker keys, and source-class indifference
- **Requirement:** REQ-005
- **Input:** one detector instance, `cfg` as in fixtures. Seed `ctxA.Key` with `steadySeq` (mean≈100) and `ctxB.Key` with a completely different steady sequence `[10000, 10010, 9990, 10005, 9995]` (mean≈10000). Then call `d.Inspect(text(105), ctxA)` (an outlier relative to A's baseline, not B's) and `d.Inspect(text(10500), ctxB)` (an outlier relative to B's baseline). Also seed `ctxShared.Key` and `ctxUnbound.Key` each with their own five-sample steady sequence and confirm an outlier on one does not affect the other. Finally, re-seed a fresh detector with `steadySeq` under `ctxA`, then call `d.Inspect(text(farBoundary), ctxAOtherSource)` (same `Key` as `ctxA`, different `SourceClass`).
- **Expected:** `Inspect(text(105), ctxA)` flags (anomalous for A); `Inspect(text(10500), ctxB)` flags (anomalous for B); a **control** call `d.Inspect(text(10005), ctxB)` (a value well inside B's normal range) does **not** flag, proving `105`-scale values are not universally anomalous, only relative to A. `ctxShared.Key`/`ctxUnbound.Key` behave identically to any other key pair: independent buffers, independent flags. `Inspect(text(farBoundary), ctxAOtherSource)` flags **identically** to the equivalent call with `ctxA` (same result as TC-003's `farBoundary` case): `SourceClass` has zero effect on the outcome, only `Key` matters.
- **Edge cases:** interleaved calls (`A, B, A, B, ...`) produce identical per-key results to calling all of `A`'s sequence followed by all of `B`'s sequence (order across keys does not matter, only order within a key).

### TC-006: `validate_write` response shape unaffected; flag is additive
- **Requirement:** REQ-006
- **Input:** guard `g` opted into `SizeAnomalyDetector(cfg)` via `WithWriteInspector`. Write five normal-sized benign entries under `keyA`'s identity to seed the baseline (`g.ValidateWrite(text, idA)` five times, sizes matching `steadySeq`). Then: (a) write one oversized **benign, PII-free, non-injection** entry under the same identity; (b) write one oversized entry that **also** contains an email address (PII) under the same identity; (c) write one oversized entry that also trips `injection_suspected` under the same identity.
- **Expected:** (a) `{"allow": true, "stored_id": "mem-...", "flags": ["size_anomaly_suspected"]}`, entry persists (a follow-up `validate_read` finds it). (b) `{"allow": true, "stored_id": "mem-...", "flags": [...]}` where `flags` contains **both** `"pii:EMAIL"` and `"size_anomaly_suspected"` (order-independent, checked as a set), and PII is redacted in the stored content as usual. (c) `{"allow": false, "stored_id": null, "flags": [...]}` where `flags` contains `"injection_suspected"` and **does not** contain `"size_anomaly_suspected"` (the write-gate rejects before `Inspect` is ever called, per task 018's "after the fail-closed check" ordering; the size baseline for `keyA` is also unchanged by this rejected call, verified by a follow-up normal-sized write not flagging).
- **Edge cases:** the response has exactly three top-level keys (`allow`, `stored_id`, `flags`) in every case, no `size_anomaly` sub-object or extra field ever appears.

### TC-007: `CombineInspectors` fans out and unions flags without disturbing either detector's own state
- **Requirement:** REQ-007
- **Input:** `sizeDet := NewSizeAnomalyDetector(cfg)`; `spy := &spyInspector{ret: []string{"self_reinforcement_suspected"}}` (a stand-in for task 018's detector, forced to always flag); `combined := CombineInspectors(sizeDet, spy)`. Drive the same six-call sequence as TC-001 (five `steadySeq` + one `outlier`) directly against `combined.Inspect(text(s), ctxA)`. Separately, run `sizeDet` alone against an identical six-call sequence on a fresh instance, and record its six individual results.
- **Expected:** `combined`'s first five calls return `["self_reinforcement_suspected"]` (only the spy fires, since `sizeDet` is still cold-starting); the sixth call returns a set-equal union `{"self_reinforcement_suspected", "size_anomaly_suspected"}` (order-independent, no duplicates). `sizeDet`'s own six results, whether driven through `combined` or run standalone on an identically-ordered sequence, are identical (the composite does not suppress, reorder, or duplicate calls into the wrapped detector). `spy`'s call count through `combined` is exactly 6 (one per accepted write, same as `sizeDet`'s).
- **Edge cases:** `CombineInspectors()` (zero inspectors) returns a `WriteInspector` whose `Inspect` always returns `nil`/empty (never panics); `CombineInspectors(sizeDet)` (a single inspector) behaves identically to calling `sizeDet` directly (no accidental double-invocation).

### TC-008: disabled-by-default parity; live-path key alignment
- **Requirement:** REQ-008
- **Input:** two guards: `gPlain := NewMemoryGuard(NewNativeDetector())` (no `WithWriteInspector` call) and `gWired := gPlain.WithWriteInspector(NewSizeAnomalyDetector(cfg))`. Drive an identical sequence of six writes (five normal + one oversized, same identity, same content) through each guard independently.
- **Expected:** `gPlain`'s six responses are byte-for-byte identical to the current (pre-019, pre-018) write-gate baseline behavior: `flags` never contains `size_anomaly_suspected` on any of the six calls, including the oversized one. `gWired`'s sixth response contains `size_anomaly_suspected`. A **key-alignment** check: write under `idA` (`spiffe_id: "spiffe://secure-agents/agent/alpha"`, attested) and separately under `idAUnattested` (same `spiffe_id`, `trust_tier: "unattested"`, which binds to `unboundKey` per `boundKeyFor`); confirm the size baseline used by the detector for the unattested write is keyed by `unboundKey`, not the raw `spiffe_id` string, by seeding five unattested writes then confirming an oversized **attested** write under the same `spiffe_id` (now landing in a *different* key, the attested `Subject()`) does not inherit the unattested baseline and correctly starts cold (per TC-004).
- **Edge cases:** construct the guard the way `main.go`'s `serve`/`write` subcommands do (through whatever config factory task 018 adds) and confirm, via the same spy technique used in task 018's own TC-008, that the **live CLI construction path** wires `SizeAnomalyDetector` when the corresponding config/flag is set (mirrors the project's "trace producer to consumer" rule and task 018's own dead-wire mutation probe).

### TC-009: concurrency safety
- **Requirement:** REQ-009
- **Input:** `d := NewSizeAnomalyDetector(cfg)`. Launch 50 goroutines, each calling `d.Inspect(text(100+i), ctxA)` 20 times with a deterministic size per goroutine (goroutine `i` always submits `100+i`), all racing against the same key; run under `go test -race`. Repeat with `CombineInspectors(d, spy)` wrapping the same concurrent load.
- **Expected:** no data race reported in either configuration; after all goroutines complete, the buffer for `ctxA.Key` holds exactly `WindowSize` entries (no partial/corrupted writes, no panic, no lost updates causing a shorter-than-expected buffer), each a valid value from the submitted set. Through `CombineInspectors`, `spy`'s recorded call count equals the total number of `Inspect` calls made (1000), matching `d`'s own observed call count.
- **Edge cases:** repeat the first scenario with 50 goroutines each writing to its **own** distinct key concurrently, confirming no cross-key corruption under concurrent map access (a second `-race`-covered subtest).

### TC-010: stdlib-only
- **Requirement:** REQ-010
- **Input:** inspect `detector_size.go`'s import block after implementation; run `go list -m all` and `git diff go.mod`.
- **Expected:** the import block contains only standard-library packages (e.g. `math`, `sync`); `go.mod` has no `require` block (unchanged from the current require-free state); `go list -m all` reports only the module itself.
- **Edge cases:** none; this is a static/textual check, not a runtime assertion.

### TC-011: ADR and spec propagation
- **Requirement:** REQ-011
- **Input:** inspect the tree after the feat commit.
- **Expected:** a new ADR exists in `docs/architecture/decisions/` (next free number after the last one present at execution time) recording the statistical method (bounded ring buffer, mean/stddev), the compare-then-update ordering, the zero-variance edge case, the `CombineInspectors` fan-out decision, and the explicit "flags, does not block" policy-engine boundary pointing at task 022. `docs/spec/interfaces.md` documents `size_anomaly_suspected` as a possible `flags` entry, `SizeAnomalyDetector` as a second entry under the `WriteInspector` extension point task 018 establishes, and `CombineInspectors`. `docs/spec/behaviors.md` describes the non-blocking behavior. `docs/spec/data-model.md` describes the per-key size-baseline state (what it is keyed by, what it stores). `docs/spec/configuration.md` documents `WindowSize`/`SigmaThreshold`/`MinSamples` and their defaults. All four spec files and the ADR land in the same commit as the code.
- **Edge cases:** the spec is rewritten in place (no appended "update:" paragraphs); no future-tense statements enter `docs/spec/`; `docs/CONTRACT.md`'s `validate_write` row is checked and updated only if it enumerates flag values explicitly (matching how task 016 handled its own additive change).
