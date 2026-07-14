# ADR-018: `SizeAnomalyDetector`, a second `WriteInspector`, plus `CombineInspectors` fan-out

**Status:** Accepted
**Date:** 2026-07-14
**Task:** [019 (Size-anomaly detector)](../../tasks/completed/019-size-anomaly-detector.md)
**Relates to:** ADR-016 (the `WriteInspector` seam this detector plugs into, unchanged), ADR-002 (the stateless `Detector` seam it sits beside), ADR-008 (the tracer-validated `validate_write` shape it leaves byte-identical), ADR-004/ADR-013 (the `boundKeyFor` identity key it groups baselines by).

## Context

The `WriteInspector` seam (ADR-016) is the block's stateful behavioral-detection seam. Task 018 shipped its first implementation, `SelfReinforcementDetector`, which catches repetitive self-authored writes. A second behavioral signal is orthogonal to repetition: a write whose byte size is far larger (or smaller) than a key's own recent history. An unexpectedly large write can signal exfil staging (an agent parking a large blob for later retrieval) or a bulk poisoning payload (many injected instructions in one write to raise the odds one survives detection). No single write is inherently suspicious out of context; only one anomalous relative to that key's own baseline. That is exactly the cross-write, stateful signal the `WriteInspector` seam exists for, and it cannot be expressed behind the stateless `Detector` seam.

This ADR also resolves a wiring gap: `MemoryGuard` holds exactly one `WriteInspector` field (ADR-016's `WithWriteInspector` is singular). Running a second behavioral detector alongside the first needs a composition point that does not change the guard's wiring surface.

## Reconciliation with ADR-016's shipped seam

Task 019's planning assumed a `WriteContext{Key, SourceClass}` struct and an `Inspect(content string, ctx WriteContext) []string` method wired via `WithWriteInspector`. The shipped ADR-016 seam matches that assumption exactly, so no signature translation was needed. Deltas worth recording:

- The seam shipped as **ADR-016** (the assumption referred to it as an unnumbered "task 018 ADR"). This ADR is numbered **018** (pinned to avoid a collision with a concurrent task claiming the next free number); the seam it depends on is ADR-016.
- `MemoryGuard`'s constructor is **variadic** (`NewMemoryGuard(det Detector, store ...MemoryStore)`), defaulting the store to `InMemoryStore`. `SizeAnomalyDetector` is unaffected (it holds its own state, not the guard's).
- ADR-016's guard passes the **raw pre-redaction `text`** to `Inspect`, not the post-PII-redaction content. `SizeAnomalyDetector` sizes on whatever content it receives (`len(content)`), so it is wiring-agnostic; on the live path it therefore sizes the raw write bytes. For PII-free writes (the common case and every size fixture) raw and redacted length are identical.

## Decision

**Ship `SizeAnomalyDetector` (`detector_size.go`) as a second `WriteInspector` behind the unchanged ADR-016 seam, flagging `size_anomaly_suspected` (additive, non-blocking) when a write's `len(content)` deviates beyond a configured sigma threshold from that key's rolling baseline; and add a `CombineInspectors` fan-out composite so both behavioral detectors run through the single `WithWriteInspector` field.**

### 1. Statistical method: bounded per-key ring buffer, mean + population stddev

Per `WriteContext.Key`, the detector keeps a bounded ring buffer of the `WindowSize` most recent write sizes (bytes). On each `Inspect` it computes the arithmetic mean and the **population** standard deviation (divide by n, not n-1) over that buffer, then applies the anomaly test. Population stddev is the correct measure here: the buffer *is* the whole observed window, not a sample drawn from a larger population. The computation is stdlib-only (`math` for `Abs`/`Sqrt`, plus a `map[string][]int`), so `go.mod` stays require-free.

`SizeAnomalyConfig{WindowSize, SigmaThreshold, MinSamples}` is passed to `NewSizeAnomalyDetector`. Documented defaults are `WindowSize=20`, `SigmaThreshold=3.0`, `MinSamples=5`; any non-positive field resolves to its default, so a zero-value config is a valid default config and the detector can never be misconfigured into a divide-by-zero or an always-flagging state.

**Rejected alternative: cross-key or global size baseline** ("large relative to the whole store"). A different statistical question, out of scope; this detector is strictly per-key, matching the tenant isolation the store already enforces.

### 2. Compare-then-update ordering

The anomaly test for a sample runs against the baseline built from the key's **existing** buffer (the samples before this one), and only afterward is the new size appended (evicting the oldest at `WindowSize` capacity). So an anomalous write never dilutes the baseline it is judged against: a single large outlier flags on the write that introduces it, computed against the prior normal history, before it is folded into the window. This ordering is the load-bearing correctness property of the detector; a unit test asserts both that the outlier flags on first sight and that the post-call buffer holds exactly the expected evicted-and-appended contents.

A consequence with a small window: once a genuine outlier is (correctly) appended, a second identical outlier is compared against a buffer that now contains the first one, so the mean shifts and the standard deviation balloons, and the second may not flag. That is the correct behavior of a rolling baseline, not a bug.

### 3. Anomaly test and the zero-variance edge

Flag `size_anomaly_suspected` iff the key's buffer already holds at least `MinSamples` samples **and** `abs(size - mean) > SigmaThreshold * stddev` (strict `>`, so a value landing exactly on the computed cutoff does not flag). The `MinSamples` gate is cold-start safety: the first `MinSamples - 1` writes for a fresh key never flag, however wildly their sizes vary, because the buffer is still seeding a baseline rather than being one.

**Zero-variance edge:** when every prior sample is identical, `stddev == 0` and the cutoff `SigmaThreshold * 0` is `0`. Then any `size != mean` flags (there is no "within N sigma" band around a single repeated value) and `size == mean` does not. This falls out of the strict-`>` test with no special-casing.

### 4. `CombineInspectors` fan-out composite

`CombineInspectors(inspectors ...WriteInspector) WriteInspector` returns a composite whose `Inspect` calls each wrapped inspector in order and returns the order-stable, deduplicated **union** of their flags. It lets an operator wire `WithWriteInspector(CombineInspectors(selfReinforcement, sizeAnomaly))` and get both detectors' findings without `MemoryGuard` gaining a second field. The composite holds an immutable slice of wrapped inspectors and no mutable state of its own, so it needs no locking beyond what each wrapped inspector already provides; combining does not change any wrapped detector's own per-call behavior or state (each still sees every accepted write exactly once, in order). `nil` inspectors are dropped at construction so a disabled detector composes cleanly; `CombineInspectors()` with no inspectors is a no-op that always returns nil.

On the live `serve` / `write` path, `main.go`'s `buildWriteInspector` factory enables both behavioral detectors by default and composes them via `CombineInspectors`; each has its own env off-switch (`MEMGUARD_SELF_REINFORCEMENT=off`, `MEMGUARD_SIZE_ANOMALY=off`), and when exactly one is enabled the factory returns it directly (no needless fan-out).

**Rejected alternative: give `MemoryGuard` a slice of `WriteInspector`s.** That changes ADR-016's wiring surface (its disabled-by-default control constructs a guard with no `WithWriteInspector` call, implying a singular field) for no gain over composing behind the existing single field.

### 5. Concurrency

`SizeAnomalyDetector` guards its per-key map with its own `sync.Mutex`, independent of `MemoryGuard.mu` and of the self-reinforcement detector's lock, so it is safe for concurrent `Inspect` calls without relying on the caller's lock scope. `go test -race` is clean across concurrent same-key and distinct-key load, standalone and through `CombineInspectors`.

### 6. Policy boundary: flags, does not block

`size_anomaly_suspected` is **additive and non-blocking**, exactly like `self_reinforcement_suspected` (ADR-016 §3). A write carrying only this flag is still `{ "allow": true, "stored_id": "mem-…" }` and still persists; the tracer-validated `{allow, stored_id, flags}` shape is byte-for-byte unchanged. Whether a size anomaly should block, quarantine, or require review is a **policy-engine decision**, out of scope here and re-homed to **task 022** (quarantine outcome), which would consume this flag. The detector observes and computes; it does not act. The fail-closed injection path is untouched: the inspector runs only on the accepted path, so a rejected poisoned write never reaches it, never carries the flag, and never enters the size baseline.

## Consequences

- A second behavioral signal ships behind the unchanged ADR-016 seam, with zero `guard.go` / `ipc.go` / contract changes: `guard.go` was not modified by this task. The only guard-adjacent edit is `main.go`'s wiring factory.
- `docs/CONTRACT.md` needs no edit: the `flags []string` shape already admits new string values.
- Known limitation, not solved here: an attacker who slowly ramps write sizes can drag the rolling mean upward and normalize an eventually-large payload (adaptive-baseline poisoning). This is inherent to any rolling-baseline detector; a follow-up (for example a slower long-horizon baseline alongside the fast window, or an absolute ceiling) is future work.
- The baseline is in-memory only and lost on restart, matching the default `InMemoryStore`. Durability is a separate future task if ever needed.
