# Task 005: Publish / remote follow-up (git remote + push)

**Project:** memory-guard
**Created:** 2026-06-19
**Status:** backlog (not started)

> The remaining item from [TODO.md](../../../TODO.md) after the Apache-2.0 relicense: the repo has **no
> git remote** yet. This task creates one and publishes, after confirming intended visibility.

## Goal

Create a git remote for memory-guard and push, with intended **public/private visibility confirmed
first** (TODO.md item 2). Keep the Apache-2.0 adoption package intact (LICENSE, NOTICE, CONTRIBUTING +
DCO, `.github/FUNDING.yml`, `.github/workflows/dco.yml`) and ensure every first-party `.go` file still
carries its `// SPDX-License-Identifier: Apache-2.0` header (TODO.md item 1 is done; keep it true for
any files added by tasks 001–004).

## Context

- Source: [TODO.md](../../../TODO.md) — "Publish — no git remote exists yet. Create one and push when
  ready, confirming intended public/private visibility first." SPDX headers (item 1) are already done;
  this task keeps that invariant as the codebase grows.
- Sibling precedent: vault is also public, Apache-2.0, **no remote yet** (per the ecosystem notes) —
  match its posture; confirm with the operator before pushing anything public.
- **Operator decision required:** the GitHub org/owner and **public vs. private** visibility. The real
  origin for the ecosystem is `tkdtaylor/*` (per agent-builder memory); confirm `tkdtaylor/memory-guard`
  vs. an alternative before creating the remote.
- Reference: [`docs/architecture/decisions/001-foundational-stack.md`](../../architecture/decisions/001-foundational-stack.md)
  §8 (Apache-2.0), the existing `LICENSE` / `NOTICE` / `CONTRIBUTING.md`.

## Requirements

| Req ID | Description | Priority |
|--------|-------------|----------|
| REQ-001 | Confirm intended visibility (public/private) and owner with the operator **before** creating the remote (ask-first — this is an irreversible publish step for a public choice). | must have |
| REQ-002 | Create the git remote (`gh repo create tkdtaylor/memory-guard …` or operator-specified) and push `master` + tags; confirm the push succeeded and the tree matches local. | must have |
| REQ-003 | Verify the Apache-2.0 adoption package is intact on the remote (LICENSE, NOTICE, CONTRIBUTING/DCO, FUNDING, dco workflow) and that the DCO check is wired. | should have |
| REQ-004 | Verify every first-party `.go` file carries the SPDX header (including any added by tasks 001–004) before the push; CI/`go build` clean. | must have |
| REQ-005 | Update [TODO.md](../../../TODO.md) to mark "Publish" done (remote URL recorded), keeping it as the historical follow-up record. | should have |

## Readiness gate

- [x] Test spec `005-publish-remote-followup-test-spec.md` exists in `docs/tasks/test-specs/`
- [ ] **Operator-confirmed** owner + public/private visibility (REQ-001 — blocks execution)

## Acceptance criteria

- [ ] [REQ-001] Visibility + owner confirmed by the operator (TC-001 — gate).
- [ ] [REQ-002] Remote created; `master` + tags pushed; remote tree matches local (TC-002).
- [ ] [REQ-003] Adoption package present on the remote; DCO check wired (TC-003).
- [ ] [REQ-004] SPDX header on every first-party `.go`; `go build ./...` clean (TC-004).
- [ ] [REQ-005] TODO.md "Publish" marked done with the remote URL (TC-005, doc check).

## Verification plan

- **Highest level achievable:** **L6** — operator-observed: the remote exists at the confirmed
  URL/visibility and `git push` succeeds; `gh repo view` / the GitHub UI shows the pushed tree and the
  DCO workflow.
- **Level 2/3 — local pre-push checks:** `go build ./... && go test ./...` green; an SPDX-header grep
  over `*.go` shows the header on every first-party file (TC-004).
- **Level 6 — operator observation:** `git remote -v` shows the new origin; `git push` exit 0;
  `gh repo view <owner>/memory-guard` confirms visibility + the adoption files. This is the evidence
  that earns ✅. **This task is largely operational — it must not be marked done from a local run alone;
  the remote must actually exist and the push must succeed.**
</content>
