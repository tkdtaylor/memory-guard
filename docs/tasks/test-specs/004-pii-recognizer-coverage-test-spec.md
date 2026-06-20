# Test Spec 004: PII recognizer coverage hardening (behind the `Detector` seam)

**Linked task:** [`docs/tasks/backlog/004-pii-recognizer-coverage.md`](../backlog/004-pii-recognizer-coverage.md)
**Written:** 2026-06-19

> Authored ahead of execution. `RedactPII` is a pure function over the new recognizer set, so the whole
> task is **fully locally verifiable** via `go test` against a labelled PII corpus. No network, no
> daemon. Use **synthetic** PII only — never real personal data in fixtures.

## Requirements coverage

| Req ID | Test cases | Locally verifiable? | Covered? |
|--------|-----------|---------------------|----------|
| REQ-001 | TC-001 | ✅ | ✅ |
| REQ-002 | TC-002 | ✅ | ✅ |
| REQ-003 | TC-003 | ✅ | ✅ |
| REQ-004 | TC-004 | ✅ | ✅ |
| REQ-005 | TC-005 | ✅ (doc check) | ✅ |

## Pre-implementation checklist

- [ ] All test cases below are defined
- [ ] Expected inputs and outputs are specified for each case
- [ ] Edge cases and error paths are covered
- [ ] Every REQ-ID from the task has at least one test case
- [ ] Fixtures use **synthetic** PII only (no real personal data)

## Test fixtures

- **PII corpus** — labelled per category: positive samples (a synthetic phone number, IBAN, IPv4/IPv6,
  DOB, GitHub/AWS/Slack-style keys) and **hard negatives** (a 9-digit order id that is not an SSN, a
  semver `1.2.3.4` that is not an IP, a UUID that is not a key). Each labelled with the expected
  category or `none`.

## Test cases

### TC-001: new recognizers redact and flag their categories
- **Requirement:** REQ-001
- **Input:** run each positive sample through `RegexDetector.RedactPII`.
- **Expected:** each PII category is replaced by its `<LABEL>` placeholder and a `pii:<LABEL>` flag is
  emitted (e.g. PHONE → `<PHONE>` + `pii:PHONE`). The v0 categories (EMAIL/US_SSN/CREDIT_CARD/API_KEY)
  still redact as before.
- **Edge cases:** multiple categories in one string each redact independently with one flag each.

### TC-002: recall/precision over the corpus meets the threshold
- **Requirement:** REQ-002
- **Input:** run the full corpus; tally detections vs. labels.
- **Expected:** per-category recall + overall precision computed and asserted ≥ threshold; the numbers
  are recorded in `data-model.md`'s recognizer table.
- **Edge cases:** a category with zero detections fails the suite (no silently-broken recognizer).

### TC-003: hard negatives tracked; false-positive regressions surface
- **Requirement:** REQ-003
- **Input:** run the hard-negative subset.
- **Expected:** none of the hard negatives are redacted (order id ≠ SSN, semver ≠ IP, UUID ≠ key);
  a recognizer that over-matches a hard negative fails the precision assertion.
- **Edge cases:** record any deliberately-accepted over-match (with rationale) so it is not silent.

### TC-004: changes confined to the `Detector` seam
- **Requirement:** REQ-004
- **Input:** the diff for the task.
- **Expected:** only `detector.go` (and tests + `data-model.md`) change; `guard.go`, `ipc.go`, `main.go`,
  and the wire contract are untouched. The new recognizers are reached via the unchanged `RedactPII`
  signature.
- **Edge cases:** `NewMemoryGuard(nil)` still wires the (now broader) `RegexDetector`.

### TC-005: data-model recognizer table updated in the same commit
- **Requirement:** REQ-005
- **Input:** `docs/spec/data-model.md`.
- **Expected:** the recognizer table lists every recognizer (v0 + new) with its label and pattern
  intent, matching the code; updated in the same commit as the detector change (no drift).
- **Edge cases:** a recognizer added without a table row fails the doc check (spec-coverage hook).
</content>
