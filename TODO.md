# TODO

## Apache-2.0 relicense follow-up — SPDX headers + publish

**Context:** Relicensed PolyForm Noncommercial → Apache-2.0 in commit `a40fcc5`.
Done: `LICENSE`, `NOTICE`, README adoption sections, `CONTRIBUTING.md` (DCO),
`.github/FUNDING.yml` + `.github/dco.yml`; stale PolyForm reference fixed in
`README.md` and `CLAUDE.md`.

**Remaining:**

1. ~~**SPDX headers** — add `// SPDX-License-Identifier: Apache-2.0` as the first
   line of every first-party Go source file (`*.go`; skip generated/vendored) as
   the codebase grows. Land it as its own commit.~~ ✅ Done — all 5 first-party
   `.go` files carry the header; `go build ./...` clean. Keep adding to new files
   as the codebase grows.
2. ~~**Publish** — no git remote exists yet. Create one and push when ready,
   confirming intended public/private visibility first.~~ ✅ Done (2026-06-20) —
   remote created **private** at `https://github.com/tkdtaylor/memory-guard`,
   `main` pushed (remote HEAD matches local). Visibility confirmed **private** by
   the operator. Apache-2.0 adoption package present on the remote (LICENSE,
   NOTICE, CONTRIBUTING/DCO, FUNDING, `.github/workflows/dco.yml`).

**Acceptance:**
- ✅ SPDX header present on every first-party `.go` file.
- ✅ Git remote created (private) and the repo pushed — `tkdtaylor/memory-guard`.
