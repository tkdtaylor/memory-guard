# Task 002: Adversarial context-poisoning test-suite for the write-gate

**Project:** memory-guard
**Created:** 2026-06-19
**Status:** backlog (not started)

> The write-gate is the block's value-add (ADR-001 §1). v0 measures it against "a few regex patterns."
> This task gives it a **real, adversarial bar** — the suite the scoping doc names as the delta that
> addresses OWASP AMG's 55-case benchmark limitation.

## Goal

Build an **adversarial context-poisoning test-suite** the `validate_write` write-gate is measured
against — **MINJA-class** (persistent memory injection), **GRAGPoison-class** (RAG corpus poisoning),
and **context-window injection via tool output** cases from the scoping doc's ASI06 scenario table.
Turn the gate's quality from "passes its own examples" into a **measured recall/precision** number
against a held-out adversarial corpus, and wire it as a repeatable test target.

## Context

- Source: the project's internal design notes
  §1 ("Built delta: adversarial test suite against MINJA-class attacks"), §5 (ASI06 scenario→detector
  table), §8 (v0 acceptance: "Adversarial test suite passes").
- Gate under test: `MemoryGuard.ValidateWrite` (`guard.go`) + `Detector.DetectInjection`
  (`detector.go`). The suite measures the **gate's** decision (`allow:false` on poisoning), not just
  the regex.
- **Depends on task 001** for the recall/precision **bar**: the production `Detector` backend sets what
  "good" is. The suite can be **authored now** against `RegexDetector` (establishing the baseline and
  the harness), with the bar tightened once task 001 lands a real backend.
- Reference: [`docs/spec/behaviors.md`](../../spec/behaviors.md) B-001, [`docs/spec/SPEC.md`](../../spec/SPEC.md)
  write-gate invariant, [`docs/spec/fitness-functions.md`](../../spec/fitness-functions.md) (the
  rejected "adversarial-poisoning recall threshold" row this task makes real).

## Requirements

| Req ID | Description | Priority |
|--------|-------------|----------|
| REQ-001 | A corpus of labelled adversarial **poisoning** cases (MINJA-, GRAGPoison-, context-window-injection-class) + **benign** cases, as test fixtures the write-gate runs against. | must have |
| REQ-002 | A test harness computes **recall** (poisoning rejected / total poisoning) and **precision** (true poisoning / all rejected) of the write-gate over the corpus and asserts a threshold. | must have |
| REQ-003 | The harness asserts the gate is **fail-closed**: every case labelled poisoning that the gate rejects stores nothing (`stored_id:null`); the invariant is checked, not just the count. | must have |
| REQ-004 | False-positive cases (benign content resembling injection) are tracked so precision regressions surface; the corpus includes hard benign cases. | should have |
| REQ-005 | The suite is a repeatable target (`go test ./...` and/or a `make` target) so it runs in the verification gate; the recall/precision numbers are recorded in the spec. | must have |
| REQ-006 | The bar is parameterized so task 001's production `Detector` can raise it without rewriting the corpus. | should have |

## Readiness gate

- [x] Test spec `002-adversarial-poisoning-suite-test-spec.md` exists in `docs/tasks/test-specs/`
- [ ] Initial corpus sourced (MINJA/GRAGPoison/context-window classes represented)
- [ ] Threshold agreed for the `RegexDetector` baseline (tightened after task 001)

## Acceptance criteria

- [ ] [REQ-001] Labelled poisoning + benign corpus exists as fixtures (TC-001).
- [ ] [REQ-002] Harness computes recall + precision and asserts a threshold (TC-002).
- [ ] [REQ-003] Every rejected poisoning case stores nothing — fail-closed asserted (TC-003).
- [ ] [REQ-004] Hard-benign false-positive cases tracked; precision regressions surface (TC-004).
- [ ] [REQ-005] Repeatable target; numbers recorded in the spec (TC-005).
- [ ] [REQ-006] Threshold parameterized for a future stronger backend (TC-006).
- [ ] `go build ./... && go test ./...` green; v0 tests unchanged.

## Verification plan

- **Highest level achievable:** **L5** — the validation harness (`go test`) runs the write-gate over
  the labelled corpus and the final assertion line reports recall/precision meeting the threshold.
- **Level 2/5 — unit/harness:** `go test ./...` → `ok`; the suite's summary line (recall, precision,
  fail-closed count) is the recorded evidence.
- **No L6 needed** — this is a test-harness task; its runtime surface is the test output itself. Record
  the recall/precision numbers in `docs/spec/fitness-functions.md` (promoting the rejected row) and
  `behaviors.md` B-001.
</content>
