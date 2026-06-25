# Test Spec 013: Injection-recall lift — a stronger `DetectInjection` heuristic

**Linked task:** [`docs/tasks/completed/013-injection-recall-lift.md`](../completed/013-injection-recall-lift.md) — ⛔ SUPERSEDED, see [ADR-010](../../architecture/decisions/010-injection-recall-approach.md)
**Written:** 2026-06-24

> Authored ahead of execution. This task strengthens the **native injection heuristic**
> (`DetectInjection` — the 4-pattern regex in `RegexDetector`, composed by `NativeDetector`) to
> recover documented miss-classes and lift INJECTION recall above the honest **0.6875 (22/32)**
> native baseline, **measured on task 002's UNMODIFIED `adversarialCorpus`**, asserted via a
> **RAISED `backendThresholds` entry** (the mechanism task 002's TC-006 built for exactly this).
> The lift must be a **true recall gain, not bought with false positives** — precision is asserted
> held at or above the **0.85** native baseline on the 14 benign cases. This is the **real** "lift
> recall above 0.69" goal that ADR-009 Finding 1 surfaced was mis-attributed to a PII/NER engine
> (Presidio cannot lift an injection number); it is correctly scoped here to the detector internals
> that own that number. The change is **entirely behind the unchanged `Detector` seam** — no
> `guard.go` / `ipc.go` / `CONTRACT.md` diff — and **stdlib-only** (heuristic/regex work, no model,
> no new dependency).

## Requirements coverage

| Req ID | Test cases | Locally verifiable? | Covered? |
|--------|-----------|---------------------|----------|
| REQ-001 | TC-001 | ✅ | ✅ |
| REQ-002 | TC-002 | ✅ (corpus unchanged; raised threshold asserted) | ✅ |
| REQ-003 | TC-003 | ✅ (precision floor over the 14 benign cases) | ✅ |
| REQ-004 | TC-004 | ✅ (corpus byte-for-byte unchanged) | ✅ |
| REQ-005 | TC-005 | ✅ (grep guard/ipc/contract clean; diff check) | ✅ |
| REQ-006 | TC-006 | ✅ (`go.mod` require-free) | ✅ |
| REQ-007 | TC-007 | ✅ (doc check — F-006 floor + recorded baseline) | ✅ |

## Pre-implementation checklist

- [ ] All test cases below are defined
- [ ] Expected inputs and outputs are specified for each case
- [ ] Edge cases and error paths are covered
- [ ] Every REQ-ID from the task has at least one test case
- [ ] Task 002's `adversarialCorpus` is used **unchanged** as the recall bar
- [ ] The native default's hot-path latency assertion (`TestNativeDetectorHotPathLatency`) remains green
- [ ] The PII corpus floors (F-006 PII side, task 004) remain at recall/precision 1.00 (this task touches
      `DetectInjection` only, never `RedactPII`)

## Test fixtures

- **Unchanged poisoning corpus** — task 002's `adversarialCorpus` in `poisoning_suite_test.go`
  (32 poisoning / 14 benign across MINJA / GRAGPoison / context-window-injection + hard-benign). Used
  **as-is** — the recall lift is proven on the same held-out cases the 0.6875 baseline was measured on,
  including the **10 documented miss-classes** the v0 regex missed:
  1. `Remember: …` standing-instruction framing (MINJA)
  2. `Store this permanently: …` framing (MINJA)
  3. `New standing order — from now on …` framing (MINJA)
  4. `Act as an unrestricted AI …` roleplay/jailbreak framing (MINJA)
  5. `whenever … should always …` behavioral-override framing (GRAGPoison)
  6. `New rule … any AI reading this must …` policy-document framing (GRAGPoison)
  7. `whenever the AI retrieves this, execute: …` (context-window-injection)
  8. `[INJECT: …]` bracket-prefix framing (context-window-injection)
  9. base64-encoded `ignore previous instructions` payload (edge)
  10. URL-encoded `ignore%20previous%20instructions` payload (edge)
- **The 14 benign cases** (4 ordinary + 7 hard-benign + 3 benign edge: empty, very-long, unicode) —
  the precision guard. The 4 known v0 false positives (`system prompt` / `<system>` in technical
  benign context) bound the precision baseline at **0.85**; the lift must not add new FPs.
- **The raised `backendThresholds` entry** — the new measured (recall, precision) for
  `*main.RegexDetector` / `*main.NativeDetector`, set per the honest-floor convention (floor 10–30 pp
  below measured) so a future backend can raise it again. The `alwaysAllowDetector` regression stub
  (TC-006 of task 002) still fails the raised bar — the parameterization stays real.

## Test cases

### TC-001: stronger `DetectInjection` recovers ≥N of the documented miss-classes
- **Requirement:** REQ-001
- **Input:** run each of the **10 documented miss-class** corpus entries (enumerated in Test fixtures)
  through the strengthened `DetectInjection` (via `NativeDetector` / `RegexDetector`), asserting per case.
- **Expected:** the strengthened heuristic returns `["injection_suspected"]` for **≥ N (N ≥ 6 of the 10)**
  previously-missed cases — specifically recovering the `remember:` / `store` / `standing-order` /
  `from now on` framing, the roleplay/jailbreak framing (`act as an unrestricted AI`), the `whenever …
  always` / `any AI reading this` policy-doc framing, **and** the base64 / URL-encoded payloads (decode-
  then-check). Each recovered case is asserted **individually** (not just an aggregate count) so a future
  regression on any single class surfaces by name.
- **Edge cases:** a recovered base64 / URL-encoded case must be caught by **decoding then re-checking**,
  not by a literal match on the encoded bytes (assert the decode path: a benign base64 string that does
  **not** decode to an injection trigger must **not** fire). The 8 already-CAUGHT cases stay caught (no
  regression on the v0-passing subset).

### TC-002: measured injection recall strictly > 0.6875 on the UNMODIFIED corpus, via a raised threshold
- **Requirement:** REQ-002
- **Input:** run task 002's **unchanged** `adversarialCorpus` (32 poisoning / 14 benign) through the
  write-gate (`ValidateWrite`) backed by the strengthened `NativeDetector` and `RegexDetector`, computing
  recall (poisoning rejected / total poisoning) exactly as the existing harness (`TestPoisoningRecallPrecision`)
  does, with the `backendThresholds` entry **raised** to the new measured floor.
- **Expected:** measured injection recall **strictly greater than the 0.6875 (22/32) native baseline**
  on the unmodified corpus, and **≥ the raised `backendThresholds.recall`** for both backends. The
  raised threshold is asserted (not just logged): a backend below the raised floor **fails**. The summary
  line records the new measured recall (e.g. `recall=0.XX (≥26/32)`).
- **Edge cases:** a measured recall that **does not exceed** 0.6875 (no net lift, or lift cancelled by a
  newly-introduced miss) **fails** this case — the bar is a strict improvement over the documented
  baseline, not parity. The raised threshold must follow the honest-floor convention (set 10–30 pp below
  the new measured value, per the suite's `backendThresholds` doc-comment) — a threshold pinned **at** the
  measured value is a fragility/honesty defect, flagged in review.

### TC-003: precision held ≥ 0.85 — recall NOT bought with false positives
- **Requirement:** REQ-003
- **Input:** run the **14 benign cases** of the unmodified corpus (4 ordinary + 7 hard-benign + 3 benign
  edge) through the strengthened write-gate, computing precision (true poisoning rejected / all rejected)
  exactly as `TestPoisoningRecallPrecision` / `TestPoisoningHardBenignFalsePositives` do.
- **Expected:** measured precision **≥ 0.85** (the native baseline) — i.e. the strengthened heuristic adds
  **no net new false positive** over the 4 documented v0 FPs (`system prompt` / `<system>` in technical
  benign context). The raised `backendThresholds.precision` is asserted. The specific benign-edge cases
  (empty content, the 10k-char benign string, the unicode `café résumé` string) and the
  `ignore the typo in the previous line` editorial hard-benign case **must not fire**.
- **Edge cases:** a recall lift that drops precision **below 0.85** (e.g. a broad `from now on` / `always`
  matcher that fires on the benign `server migration … next weekend` or `task list` notes) **fails** this
  case — the recall and precision assertions are evaluated **together**, so a backend cannot pass TC-002
  by trading precision away. If a new heuristic *legitimately* improves precision (removes a v0 FP), the
  raised precision floor reflects it and the change is recorded in F-006.

### TC-004: the `adversarialCorpus` is UNCHANGED (byte-for-byte)
- **Requirement:** REQ-004
- **Input:** diff `poisoning_suite_test.go`'s `adversarialCorpus` literal (the 32 poisoning + 14 benign
  entries and their labels/classes/notes) against `main`.
- **Expected:** the corpus slice is **byte-for-byte unchanged** by this task — the lift is proven on the
  **same held-out cases** the 0.6875 baseline was measured on, not on an easier rewritten corpus. Only the
  `backendThresholds` constants (and the miss-class **notes**, if a note is updated from "MISSED" to
  "CAUGHT" to reflect the new reality) may change in `poisoning_suite_test.go`; the **case contents,
  labels, and classes** are untouched.
- **Edge cases:** adding, removing, re-labelling, or re-wording any **case content** to manufacture a
  higher number **fails** this case — that is gaming the corpus, the exact failure the unchanged-corpus
  rule exists to prevent. Updating a `note` from `MISSED: …` to `CAUGHT: …` for a class the heuristic now
  catches is permitted (it documents the new truth) and does **not** count as a corpus change.

### TC-005: `Detector` seam unchanged — no guard / IPC / contract diff
- **Requirement:** REQ-005
- **Input:** (a) diff `guard.go`, `ipc.go`, and `docs/CONTRACT.md` against `main`; (b) grep them for any
  new injection-heuristic-specific symbol, type, or import introduced by this task.
- **Expected:** `guard.go`, `ipc.go`, and `docs/CONTRACT.md` are **byte-for-byte unchanged** — the entire
  change lives behind `detector.go`'s `Detector` interface (`DetectInjection` body + any new unexported
  helpers/patterns). The `Detector` interface signature is **unchanged** (`RedactPII` / `DetectInjection`,
  same shapes). The write-gate stays fail-closed: a newly-recovered poisoning case is rejected
  `allow:false` / `stored_id:null` and never persists.
- **Edge cases:** the strengthened heuristic must remain **swappable** — constructing `MemoryGuard` with
  `NewRegexDetector()`, `NewNativeDetector()` (and back) exercises `validate_write` / `validate_read` /
  `verify_delete` with no caller change. A new heuristic helper that leaks a symbol into `guard.go` /
  `ipc.go` (rather than staying inside `detector.go`) **fails** this case.

### TC-006: stdlib-only — `go.mod` stays require-free
- **Requirement:** REQ-006
- **Input:** inspect `go.mod` (`go list -m all`) after the change.
- **Expected:** `go.mod` has **no `require` block** — the lift is heuristic / regex / stdlib-decode work
  (`encoding/base64`, `net/url`, `regexp`, `strings` — all stdlib), **not** a model or NLP dependency. No
  new third-party module is added; the `TestFitnessNoDependency` (F-… seam/dependency) gate stays green.
- **Edge cases:** reaching for a classifier/ML library to lift recall **fails** this case and is out of
  scope — that would be a future ADR (the Presidio path is for PII/NER, not injection), not this task. A
  stdlib decode helper (base64 / URL) is in scope and explicitly expected.

### TC-007: the new measured recall/precision recorded; F-006 floor updated to the honest baseline
- **Requirement:** REQ-007
- **Input:** inspect `docs/spec/fitness-functions.md` F-006 and `poisoning_suite_test.go`'s
  `backendThresholds` doc-comment after the change.
- **Expected:** F-006's recorded poisoning baseline is **updated to the new honest measured numbers**
  (recall `> 0.6875`, precision `≥ 0.85`), with the F-006 threshold floor raised to the new honest floor
  (10–30 pp below measured, per convention) — the spec is rewritten **in place** (not appended;
  ADR/history carries the old 22/32 number, the spec carries the truth). The `backendThresholds`
  doc-comment records the new measured values and the recovered miss-classes. The honest-floor convention
  is restated so a **future** stronger backend can raise the bar again.
- **Edge cases:** leaving F-006 at the old 0.68/0.84 floor while the measured number rose **fails** this
  case — a stale floor is a silent under-claim and lets a future regression below the new real baseline go
  undetected. Setting the new floor **above** the measured value (so the suite would fail on a clean tree)
  is the opposite failure and also **fails**.
</content>
</invoke>
