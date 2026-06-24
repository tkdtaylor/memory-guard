# Task 007: Presidio-backed `Detector` (un-defer ADR-002's Presidio path)

**Project:** memory-guard
**Created:** 2026-06-24
**Status:** backlog (not started)

> **Un-defers the decision ADR-002 deferred.** ADR-002 resolved the v0/v1 backend as **Go-native,
> in-process, zero new deps**, and **deferred — not foreclosed** — Presidio-as-sidecar and
> Presidio-via-ONNX. This task (roadmap **T2**) un-defers that Presidio path: it ships the block's
> **first third-party dependency** behind the **unchanged** `Detector` seam, to lift detection recall
> above the honest regex baseline. The seam is exactly what makes this an additive,
> one-implementation change.

## Goal

Implement a **Presidio-backed `Detector`** — either the **sidecar/subprocess** path (Presidio run out
of process, called over a local socket/stdio) **or** the **ONNX-in-process** path (Presidio recognizer
models loaded in-process via an ONNX runtime) — **entirely behind the unchanged `Detector` interface**
(`detector.go`), with **zero contract / guard / IPC impact**. The task **decides** sidecar-vs-ONNX and
records the choice in a **new ADR** that weighs the two against memory-guard's invariants (single
static binary, hot-path latency, minimal auditable dependency surface).

Because this is the repo's **first** external dependency (`go.mod` has no `require` block today), it is
an explicit **ask-first ADR + a blocking `dep-scan`/`code-scanner` gate** with the dependency
version-pinned. The existing `RegexDetector` and `NativeDetector` **remain selectable**; the backend is
**config-driven behind the seam** (no Presidio types leak into `guard.go` / `ipc.go` / `CONTRACT.md`).

The acceptance bar is twofold and both halves are hard:

1. **Lift recall** measurably above the honest **0.69 recall / 0.85 precision** regex/Go-native baseline
   from task 002's poisoning suite — measured on **the same** `adversarialCorpus`, without rewriting it.
2. **Re-validate the `< 1 ms` per-op hot-path latency budget** (ADR-002) with the Presidio backend
   wired — Presidio is heavier than microsecond regex, so sidecar (IPC round-trip per call) vs. ONNX
   (model inference per call) is the **real tradeoff** the ADR must weigh and the measurement must
   settle.

## Context

- Roadmap: [`docs/plans/roadmap.md`](../../plans/roadmap.md) → "Toward a true v1" row **T2** (Presidio-
  backed `Detector`, behind the unchanged seam, first third-party dep, must lift recall above the 0.69
  baseline and re-validate the `< 1 ms` budget).
- The seam this plugs into: the `Detector` interface (`RedactPII` / `DetectInjection`) in
  [`detector.go`](../../../detector.go). The Presidio backend is a **third** `Detector` implementation
  alongside `RegexDetector` and `NativeDetector`; `MemoryGuard`, `ipc.go`, and the contract do **not**
  change. Wiring point: `main.go` already constructs `NewMemoryGuard(NewNativeDetector())` — backend
  selection becomes config-driven there.
- Prior decisions: [ADR-001](../../architecture/decisions/001-foundational-stack.md) §3 (seam
  guarantee), [ADR-002](../../architecture/decisions/002-detector-backend.md) (Go-native chosen,
  Presidio **deferred** — this task un-defers it; the new ADR records the sidecar-vs-ONNX decision and
  references ADR-002 as the deferral it acts on, without superseding it).
- Baseline to beat: task 002's suite ([`poisoning_suite_test.go`](../../../poisoning_suite_test.go),
  [completed/002](../../completed/002-adversarial-poisoning-suite.md)) — **measured recall 0.69 /
  precision 0.85** over the 32-poisoning / 14-benign `adversarialCorpus`, with 10 documented miss-classes.
  The suite's `backendThresholds` is keyed by `Detector` type-name precisely so a stronger backend
  raises its bar **without touching the corpus** (TC-006 of task 002). This task adds a Presidio entry.
- Latency budget: [ADR-002](../../architecture/decisions/002-detector-backend.md) "Measured" —
  `< 1 ms` per `validate_*` op (Go-native measured ~5.6 µs). The Presidio backend must re-validate this
  budget; if a naive sidecar round-trip blows it, the ADR records the mitigation (batching, warm
  process, ONNX in-process) or the revised budget with rationale.
- **Dependency (ask-first):** the Presidio SDK / sidecar protocol **or** an ONNX runtime + the
  recognizer model is the block's **first** third-party dependency. It must clear `dep-scan` (`gods`)
  **and** `code-scanner` as **blocking** gates and be **version-pinned**, per CLAUDE.md → Recommended
  tooling. The pinned versions are recorded in the new ADR + `docs/spec/`.
- **Constraint:** the contract and the `Detector` interface are **unchanged** — the Presidio backend is
  a drop-in `Detector`. The write-gate stays fail-closed; PII stays redacted before storage and on read.
  **No Presidio specifics may leak** past the seam (no Presidio types/imports in `guard.go` / `ipc.go` /
  `docs/CONTRACT.md`).

## Requirements

| Req ID | Description | Priority |
|--------|-------------|----------|
| REQ-001 | A new **Presidio-backed `Detector`** implementation satisfies the **unchanged** `Detector` interface (`RedactPII` / `DetectInjection`); `MemoryGuard` / `ipc.go` / `CONTRACT.md` are untouched. | must have |
| REQ-002 | The Presidio backend **lifts recall above the 0.69 / 0.85 regex baseline** on task 002's **unchanged** `adversarialCorpus`, asserted via a Presidio entry in `backendThresholds` (recall floor strictly `> 0.69`); precision does not regress below the baseline floor. | must have |
| REQ-003 | The Presidio backend **re-validates the `< 1 ms` per-`validate_*` hot-path latency budget** with the backend wired; the measured figure (and, if the budget is revised, the rationale) is recorded in the new ADR. | must have |
| REQ-004 | The deployment shape — **sidecar/subprocess vs. ONNX-in-process** — is **decided and recorded in a new ADR**, weighed against the single-binary / latency / dependency-surface invariants; the ADR references ADR-002 as the deferral it acts on. | must have |
| REQ-005 | The first third-party dependency clears **`dep-scan` (blocking) + `code-scanner`** and is **version-pinned**; the pinned versions are recorded in the ADR + `docs/spec/configuration.md`. This is an **ask-first** dependency add per CLAUDE.md. | must have |
| REQ-006 | `RegexDetector` and `NativeDetector` **remain selectable**; backend choice is **config-driven behind the seam** (selected at construction in `main.go` / via config), with **no Presidio specifics leaking** into `guard.go` / `ipc.go` / `CONTRACT.md` (no Presidio types or imports past the seam). | must have |
| REQ-007 | The Presidio backend is **swappable** — a test substitutes it for `RegexDetector`/`NativeDetector` (and back) with no guard / IPC / contract change, proving the seam still carries the alternate backend. | must have |

## Readiness gate

- [x] Test spec `007-presidio-detector-backend-test-spec.md` exists in `docs/tasks/test-specs/`
- [ ] **ADR prereq** — sidecar vs. ONNX decided and an ADR drafted (ask-first; references ADR-002's deferral)
- [ ] **dep-scan prereq** — the Presidio SDK / ONNX runtime + model selected, **version-pinned**, and `dep-scan` (`gods`) **+** `code-scanner` cleared (blocking) before the dependency lands in `go.mod`
- [ ] Task 002's `adversarialCorpus` available unchanged as the recall-lift bar (it is — `poisoning_suite_test.go`)

## Acceptance criteria

- [ ] [REQ-001] Presidio-backed `Detector` satisfies the unchanged interface; guard / IPC / contract untouched (TC-001).
- [ ] [REQ-002] Recall measured **> 0.69** on the unchanged `adversarialCorpus`; precision ≥ baseline floor; Presidio `backendThresholds` entry asserts it (TC-002).
- [ ] [REQ-003] `< 1 ms` per-op latency re-validated with Presidio wired; figure recorded in the ADR (TC-003 / L6).
- [ ] [REQ-004] Sidecar-vs-ONNX decided and recorded in a new ADR referencing ADR-002 (TC-004, doc check).
- [ ] [REQ-005] `dep-scan` + `code-scanner` clear the first dependency; versions pinned + recorded (TC-005).
- [ ] [REQ-006] `RegexDetector` / `NativeDetector` still selectable, config-driven; no Presidio leak past the seam (TC-006).
- [ ] [REQ-007] Presidio backend swaps in/out behind the seam with no caller change (TC-007).
- [ ] `go build ./... && go test ./...` green; task 002's corpus unchanged; v0/v1 tests unchanged and passing.

## Verification plan

- **Highest level achievable:** **L6** — a live `go run . write`/`serve` with the Presidio backend
  selected exercises it end-to-end (PII redacted, injection flagged) and the measured hot-path latency
  is observed and recorded; plus **L5** the poisoning suite reports recall **> 0.69** on the unchanged
  corpus, and **L3** dep-scan/code-scanner clear the first dependency.
- **Level 2 — unit:** `go build ./... && go test ./...` → `ok`, incl. the seam-swap (TC-007) and the
  seam-isolation grep (TC-006).
- **Level 3 — supply-chain gate (blocking):** `gods` (dep-scan) **+** `code-scanner` on the new module
  tree (Presidio SDK / ONNX runtime + model) → pass, exit 0; versions pinned + recorded in the ADR and
  `docs/spec/configuration.md`. This gate must pass **before** the dependency merges.
- **Level 5 — harness:** the poisoning suite (`go test`) runs the **unchanged** `adversarialCorpus`
  through the Presidio backend and the summary line reports **recall > 0.69** (precision ≥ baseline
  floor); the Presidio `backendThresholds` entry asserts the lift.
- **Level 6 — operator observation:** `go run . write "contact alice@example.com"` (and a live `serve`)
  with the Presidio backend selected via config → PII `<LABEL>`-redacted, an injection input →
  write-gate rejection; latency observed and recorded in the new ADR. This is the evidence that earns ✅.
