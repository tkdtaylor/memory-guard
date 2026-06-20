# Test Spec 005: Publish / remote follow-up (git remote + push)

**Linked task:** [`docs/tasks/backlog/005-publish-remote-followup.md`](../backlog/005-publish-remote-followup.md)
**Written:** 2026-06-19

> This is an **operational** task, not a code change — its "tests" are checks on git/remote state and a
> grep for SPDX headers, not unit tests. **Execution is gated** on the operator confirming visibility +
> owner (REQ-001). Do not create a public remote without that confirmation.

## Requirements coverage

| Req ID | Test cases | Locally verifiable? | Covered? |
|--------|-----------|---------------------|----------|
| REQ-001 | TC-001 | ✅ (operator confirmation recorded) | ✅ |
| REQ-002 | TC-002 | ⚠️ needs the remote (operator-gated) | ✅ |
| REQ-003 | TC-003 | ⚠️ needs the remote | ✅ |
| REQ-004 | TC-004 | ✅ | ✅ |
| REQ-005 | TC-005 | ✅ (doc check) | ✅ |

## Pre-implementation checklist

- [ ] Operator has confirmed public/private visibility and the owner (REQ-001)
- [ ] All checks below are defined
- [ ] No public push happens before the visibility confirmation

## Test cases

### TC-001: operator confirms visibility + owner (gate)
- **Requirement:** REQ-001
- **Input:** the operator's confirmation of owner (`tkdtaylor` unless steered) and public vs. private.
- **Expected:** the confirmation is recorded in the task before any remote is created; execution does
  not proceed without it.
- **Edge cases:** if "private", the remote is created private — never default to public.

### TC-002: remote created; master + tags pushed; trees match
- **Requirement:** REQ-002
- **Input:** `gh repo create <owner>/memory-guard --<public|private> …`; `git push -u origin master --tags`.
- **Expected:** `git remote -v` shows the new origin; `git push` exits 0; `git ls-remote` / `gh repo view`
  confirms the pushed tree matches local HEAD.
- **Edge cases:** a push rejected for a protected branch / wrong default branch is surfaced, not forced.

### TC-003: adoption package present on the remote; DCO wired
- **Requirement:** REQ-003
- **Input:** inspect the remote (`gh repo view`, the GitHub UI).
- **Expected:** `LICENSE` (Apache-2.0), `NOTICE`, `CONTRIBUTING.md` (DCO), `.github/FUNDING.yml`, and
  `.github/workflows/dco.yml` are present; the DCO check is active on the repo.
- **Edge cases:** a missing adoption file is fixed before the task closes.

### TC-004: SPDX header on every first-party .go; build clean
- **Requirement:** REQ-004
- **Input:** grep the first line of every first-party `*.go` for `// SPDX-License-Identifier: Apache-2.0`;
  `go build ./...`.
- **Expected:** every first-party `.go` file (incl. any added by tasks 001–004) carries the header;
  `go build ./...` exits 0. (Generated/vendored files, if any, are exempt and noted.)
- **Edge cases:** a new file missing the header fails this check — add it before the push.

### TC-005: TODO.md "Publish" marked done with the remote URL
- **Requirement:** REQ-005
- **Input:** `TODO.md`.
- **Expected:** the "Publish" item is marked done and records the remote URL + chosen visibility,
  preserved as the historical follow-up record (not deleted).
- **Edge cases:** if the operator chose private, TODO.md records that explicitly.
</content>
