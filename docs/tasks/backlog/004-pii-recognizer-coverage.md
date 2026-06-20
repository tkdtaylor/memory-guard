# Task 004: PII recognizer coverage hardening (behind the `Detector` seam)

**Project:** memory-guard
**Created:** 2026-06-19
**Status:** backlog (not started)

> v0 ships four high-signal recognizers (EMAIL, US_SSN, CREDIT_CARD, API_KEY) as a Presidio stand-in.
> This task **broadens recognizer coverage and cuts false-negatives** — strictly behind the `Detector`
> seam, so the guard/IPC/contract are untouched — measured against a labelled PII corpus.

## Goal

Expand the PII recognizer set and reduce false-negatives so the redaction promise (PII never stored or
returned raw) holds across more categories — names, phone numbers, IBAN/bank details, dates of birth,
IP/MAC addresses, and a wider set of credential/API-key shapes (beyond the v0 `sk`/`AKIA`/`ghp`/`xox`).
All of it stays **inside `Detector` implementations** (`detector.go`) — `RegexDetector` gains
recognizers now, and task 001's production backend inherits the same corpus as its bar. Measure
recall/precision against a labelled PII corpus and record the numbers.

## Context

- Source: the project's internal design notes
  §5 (ASI06 "sensitive context leakage" / "cross-session memory leakage" scenarios — PII detector +
  protected-key monitor), §1 (Presidio is the production target; v0 `RegexDetector` is the stand-in).
- Code under change: `RegexDetector` in `detector.go` (the `pii []labeledPattern` set) — **only** the
  detector; `guard.go`/`ipc.go`/contract unchanged (the whole point of the seam).
- **Soft-relates to task 001**: that task may replace `RegexDetector` with Presidio (which already
  ships a broad recognizer set). This task is still worth doing for the v0 stand-in and to establish
  the **labelled PII corpus + recall/precision harness** that task 001's backend is then measured
  against. Coordinate so the corpus is shared, not duplicated.
- Reference: [`docs/spec/data-model.md`](../../spec/data-model.md) (the recognizer table),
  [`docs/spec/SPEC.md`](../../spec/SPEC.md) (PII-never-stored-raw invariant),
  [`docs/spec/fitness-functions.md`](../../spec/fitness-functions.md) F-002.

## Requirements

| Req ID | Description | Priority |
|--------|-------------|----------|
| REQ-001 | `RegexDetector` gains recognizers for additional PII categories (e.g. PHONE, IBAN, IP_ADDRESS, DOB, plus broader API-key/credential shapes), each emitting a `pii:<LABEL>` flag and `<LABEL>` redaction. | must have |
| REQ-002 | A labelled **PII corpus** (positive samples per category + hard negatives) drives a recall/precision harness asserting a threshold; the numbers are recorded in the spec's recognizer table. | must have |
| REQ-003 | False-positive control: hard negatives (e.g. a 9-digit order number that is not an SSN; a version string that is not an IP) are tracked so over-redaction regressions surface. | must have |
| REQ-004 | All changes stay **inside `Detector`** — `guard.go`, `ipc.go`, and the contract are untouched (the seam invariant); the new recognizers are reachable via the unchanged `RedactPII`. | must have |
| REQ-005 | The recognizer table in [`data-model.md`](../../spec/data-model.md) is updated in the same commit to list every recognizer and its pattern intent. | must have |

## Readiness gate

- [x] Test spec `004-pii-recognizer-coverage-test-spec.md` exists in `docs/tasks/test-specs/`
- [ ] PII corpus sourced/synthesized (positives per category + hard negatives — no real PII)
- [ ] Coordination with task 001 confirmed (shared corpus, not duplicated)

## Acceptance criteria

- [ ] [REQ-001] New recognizers added with `<LABEL>` redaction + `pii:<LABEL>` flags (TC-001).
- [ ] [REQ-002] Recall/precision harness over the corpus asserts a threshold; numbers recorded (TC-002).
- [ ] [REQ-003] Hard negatives tracked; false-positive regressions surface (TC-003).
- [ ] [REQ-004] Changes confined to `detector.go`; guard/IPC/contract untouched (TC-004).
- [ ] [REQ-005] `data-model.md` recognizer table updated in the same commit (TC-005, doc check).
- [ ] `go build ./... && go test ./...` green; v0 PII tests unchanged and passing.

## Verification plan

- **Highest level achievable:** **L5** — the validation harness (`go test`) runs the PII corpus through
  `RedactPII` and the final assertion reports recall/precision meeting the threshold; no runtime daemon
  needed (pure detector function).
- **Level 2/5 — unit/harness:** `go test ./...` → `ok`; the corpus summary line (per-category recall +
  precision) is the recorded evidence.
- **No L6 needed** — `RedactPII` is a pure function; its surface is the test output. Record the numbers
  in `data-model.md`'s recognizer table. (A `go run . write` with a multi-PII string is an optional
  smoke observation.)
</content>
