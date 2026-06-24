# Configuration

**Project:** memory-guard
**Last updated:** 2026-06-24 (task 010 — AuditConfig)

Every knob the system exposes. memory-guard is configured by **command-line flags** only — there are
no config files, no application environment variables, and no secrets in v0.

Not here: what gets configured ([behaviors.md](behaviors.md)); the parsing lives in `main.go`.

---

## Configuration files

**None.** No config file. The socket path is supplied inline via `--socket`; the content to validate
is supplied inline as the `write` / `read` argument or in the IPC request. There is no external policy
source, no YAML policy engine, and no store path (the store is in-memory only).

---

## Runtime flags

| Flag | Subcommand | Type | Default | Required | Effect |
|------|------------|------|---------|----------|--------|
| `--socket` | `serve` | string (path) | — | yes (serve) | Unix socket to bind; a stale socket at the path is removed first; bound `0600`. Missing → `serve: --socket is required`, exit `2` |

`write` and `read` take a single positional text/query argument (absent → the empty string). A missing
subcommand or an unknown subcommand → usage error (exit `2`).

---

## Socket permissions

The `serve` socket is bound `0600` (owner-only) — a filesystem-ACL restriction so other uids cannot
connect (`ipc.go::serve` calls `os.Chmod(socketPath, 0o600)` after binding). Unlike vault's
secret-handling socket, memory-guard's v0 socket has **no `SO_PEERCRED` peer-uid check** — the `0600`
mode is the only restriction. Adding a kernel-verified peer-uid gate is a candidate v1 hardening,
tracked as a limitation rather than a config knob.

---

## Environment variables

**Application:** none. memory-guard reads no application environment variables in v0.

**Hook profile env vars** (consumed by `.claude/scripts/`, not the application):
- `CLAUDE_HOOK_PROFILE` — `minimal` / `standard` / `strict` (default `standard`)
- `CLAUDE_DISABLED_HOOKS` — comma-separated list of hook names to disable

---

## Secrets

memory-guard handles no secrets of its own — it holds no master key, no credentials, no tokens. Its
job is the opposite: to keep **PII** (which it sees in agent content) out of the stored memory and out
of every response, via redaction (`<LABEL>` placeholders) on write and read. It never stores raw PII,
never returns the raw stored value (only an opaque `stored_id`), and never writes any content to the
repo.

| Sensitive data | Source | Handling |
|----------------|--------|----------|
| PII in agent content (emails, SSNs, cards, API keys) | supplied at runtime via `validate_write` / `validate_read` | redacted to `<LABEL>` before storage and again on read; the raw form is never stored or returned |

**Rule:** real PII / credentials are never pasted into chat, logged, or written into the repo. The
`protect-secrets` hook blocks writes to common credential filenames. The test fixtures
(`alice@example.com`, `123-45-6789`) are obvious non-secret placeholders.

---

## Deployment configuration

| Aspect | Value | Notes |
|--------|-------|-------|
| Artifact | single static Go binary (`memory-guard`) | `go build ./...` / `make build` → `bin/memory-guard` |
| Socket | Unix domain socket at `--socket` path | `chmod 0600`; co-located with the agent, not network-exposed; no `SO_PEERCRED` gate in v0 |
| Ports exposed | none | memory-guard binds no TCP port; IPC is the Unix socket only |
| On-disk store | none | the store is in-memory only; nothing persists across a restart |
| Runtime dependencies | **none (Go standard library only)** | no third-party modules in v0; the first will be the Presidio-backed `Detector` (sidecar / ONNX), a future ADR + `dep-scan` / `code-scanner` blocking gate |

---

## Audit emission configuration

Audit emission is controlled **programmatically** (not via CLI flags or env vars in v0) through the
`AuditConfig` struct injected via `(*MemoryGuard).WithAudit`. This is a code-level knob, not an
operator-visible flag — the operator wires the config at construction time (`main.go` / `ipc.go`).

| Field | Type | Default | Effect |
|-------|------|---------|--------|
| `AuditConfig.Enabled` | bool | `false` | `false` → emission disabled (default until audit-trail endpoint confirmed). `true` enables emission only when `Sink` is also non-nil |
| `AuditConfig.Sink` | `AuditSink` | `nil` | The transport implementation (socket/HTTP/file). `nil` with `Enabled=true` fails closed to disabled (no emission, no crash) |

**Default:** emission is **disabled** (`AuditConfig{}` zero value). The guard ships with emission off
until the sibling audit-trail emit endpoint is confirmed live (ADR-007).

**Invalid config** (`Enabled=true, Sink=nil`): fails closed to disabled — no emission, no crash. This
is the documented safe degradation for a misconfigured sink.

---

## Defaults policy

Defaults are **safe / fail-closed**: the write-gate rejects suspected poisoning by default (a write is
suspect until it passes detection); PII is redacted by default on both write and read; `--socket` has
no default (the operator must name it explicitly rather than risk binding a surprise path); audit
emission is **disabled by default** (fail-open for the sink, fail-closed for the write-gate). No path
stores poisoned content or returns raw PII.
</content>
