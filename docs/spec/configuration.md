# Configuration

**Project:** memory-guard
**Last updated:** 2026-07-14 (task 021: named-key write-time policy via `MEMGUARD_PROTECTED_KEYS` / `MEMGUARD_IMMUTABLE_KEYS`, ADR-017; task 017: opt-in audit emission via `serve --audit-socket` / `MEMGUARD_AUDIT_SOCKET`, ADR-014; task 015: file-backed store selection, ADR-012)

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
| `--audit-socket` | `serve` | string (path) | — | no | Opt-in audit-trail emit socket (ADR-014). Absent/empty → emission disabled. Wins over `MEMGUARD_AUDIT_SOCKET`. An unreachable path is **not** a startup error (fail-open soft dependency) |

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

**Application:**

| Variable | Values | Default | Effect |
|----------|--------|---------|--------|
| `MEMGUARD_DETECTOR` | `regex` \| `native` \| `presidio` | `native` | Selects the `Detector` backend at construction (`main.go` → `NewDetectorFromConfig`). `native` (default) = the Go-native in-process backend (ADR-002, `< 1 ms` hot path). `regex` = the v0 RegexDetector. `presidio` = the opt-in Presidio-backed sidecar (ADR-009, milliseconds/op, richer PII/NER recall). An unknown value is a fail-closed construction error, exit `2` — never a silent fallback. The value names a backend STRING only; no backend Go type leaks into the seam-protected files. |
| `MEMGUARD_STORE` | `memory` \| `file` | `memory` | Selects the `MemoryStore` backend at construction (`main.go` → `NewStoreFromConfig`). `memory` (default) = the ephemeral in-memory map (`InMemoryStore`), unchanged v0 behavior. `file` = the persistent file-backed adapter (`FileStore`, ADR-012): a JSONL snapshot rewritten atomically on every mutation, read through to disk on every verb, so `verify_delete`'s absence proof and the residue scan run against real persistence. An unknown value is a fail-closed construction error, exit `2` (never a silent fallback). The value names a backend STRING only; no store Go type leaks into the seam-protected files. |
| `MEMGUARD_STORE_PATH` | absolute path | — | Path to the JSONL store file, **required when `MEMGUARD_STORE=file`** (`file` with no path is a fail-closed construction error, exit `2`, never a silent default location). Ignored for `memory`. The file (and its `<path>.tmp` sibling during a rewrite) is bound mode `0600`. |
| `MEMGUARD_SELF_REINFORCEMENT` | any \| `off` | on | Off-switch for the `SelfReinforcementDetector` behavioral `WriteInspector` (ADR-016) on the `serve` / `write` path. `off` disables it; any other value (including unset) leaves it on. |
| `MEMGUARD_SIZE_ANOMALY` | any \| `off` | on | Off-switch for the `SizeAnomalyDetector` behavioral `WriteInspector` (ADR-018) on the `serve` / `write` path. `off` disables it; any other value (including unset) leaves it on. When both behavioral detectors are on they run together, composed via `CombineInspectors`. |
| `MEMGUARD_PROTECTED_KEYS` | comma-separated `path.Match` globs | — (empty) | Operator-configured **protected** key patterns for the named-key write-time policy (ADR-017), wired into `serve`'s guard via `NewKeyPolicyFromConfig` → `WithKeyPolicy`. An unattested/absent write to a `key` matching one of these globs is flagged `protected_key_violation` but **allowed** (flag-only). Whitespace around each entry is trimmed; empty entries are dropped. A **malformed** glob is a fail-closed construction error (exit `2`, wrapping `path.ErrBadPattern`), never a silently-dropped pattern. Empty/absent leaves only the always-on reserved `memguard:` namespace active. Reserved keys are enforced fail-closed regardless of this var. |
| `MEMGUARD_IMMUTABLE_KEYS` | comma-separated `path.Match` globs | — (empty) | Operator-configured **immutable** key patterns (ADR-017), same parsing/fail-closed rules as `MEMGUARD_PROTECTED_KEYS`. A `key` matching one of these globs is baselined on its first accepted write; a later write whose redacted content drifts from that pinned baseline is flagged `immutable_mismatch` but **allowed** (flag-only). The baseline registry is in-process only (lost on restart, a documented durability limitation). |

**Hook profile env vars** (consumed by `.claude/scripts/`, not the application):
- `CLAUDE_HOOK_PROFILE` — `minimal` / `standard` / `strict` (default `standard`)
- `CLAUDE_DISABLED_HOOKS` — comma-separated list of hook names to disable

---

## Presidio detector backend (opt-in, ADR-009)

Selected by `MEMGUARD_DETECTOR=presidio`. The Go binary stays **pure-Go / stdlib-only** (`go.mod`
remains `require`-free); the Presidio dependency runs **out-of-process** as a Python **sidecar**
(`presidio/sidecar.py`), spoken to over newline-delimited JSON on the subprocess's stdin/stdout. The
sidecar needs **no outbound network at runtime** (the spaCy model is local and pinned).

**Pinned, BASE-ONLY dependency set** (`presidio/requirements.txt`):

| Package | Pinned version | Notes |
|---------|----------------|-------|
| `presidio-analyzer` | `2.2.362` | base install only — NO azure/openai/transformers/gliner/stanza extras |
| `presidio-anonymizer` | `2.2.362` | base install only |
| `spacy` | `3.8.14` | NER engine |
| `en_core_web_lg` | `3.8.0` | spaCy model — installed via `python -m spacy download en_core_web_lg` |

**Provisioning:** `python3 -m pip install -r presidio/requirements.txt && python3 -m spacy download en_core_web_lg`.

**Why base-only:** the dependency scan flagged credential-reading code as living **only** in the
optional extras (azure / openai / langextract / transformers / gliner / stanza); a base install never
pulls them. **DO NOT** add those extras — they reintroduce that surface. `dep-scan` over the pinned
packages: all security checks pass (install_scripts / obfuscation / vulnerability / typosquatting /
maintainer_change / dependency_confusion), with one informational `pypi_provenance` WARN accepted by
operator decision (pip hash-pinning mitigates the sole-source-of-integrity note). See ADR-009.

**Fail-closed degradation:** if the sidecar is unavailable (not provisioned, crashed), the Presidio
backend falls back to native structured redaction — PII is **still redacted, never passed through
raw** — and surfaces no Presidio-typed error past the seam. The `native` default backend has no such
dependency and is unaffected.

---

## Behavioral write-inspector configuration

The two behavioral `WriteInspector` detectors (ADR-016, ADR-018) are on by default on the `serve` /
`write` path and toggled by the `MEMGUARD_SELF_REINFORCEMENT` / `MEMGUARD_SIZE_ANOMALY` env vars above.
On the CLI path they run with their code defaults (no per-knob env or flag surface in v0); the knobs
below are set through the constructors (`NewSelfReinforcementDetector` options, `NewSizeAnomalyDetector(SizeAnomalyConfig{})`)
and are what tests and any embedding caller tune.

**`SizeAnomalyDetector` (`SizeAnomalyConfig`, ADR-018):**

| Knob | Type | Default | Effect |
|------|------|---------|--------|
| `WindowSize` | int | `20` | Number of most-recent write sizes retained per key (the bounded ring-buffer capacity). Older sizes are evicted once full. A non-positive value resolves to the default. |
| `SigmaThreshold` | float64 | `3.0` | Number of population standard deviations from the key's rolling mean beyond which a write is flagged (strict `>`). A non-positive value resolves to the default. |
| `MinSamples` | int | `5` | Minimum prior samples a key's buffer must already hold before any write can be flagged (cold-start guard). A non-positive value resolves to the default. |

A zero-value `SizeAnomalyConfig{}` resolves every field to its default, so the detector is never
misconfigured into a divide-by-zero or an always-flagging state. The detector sizes on `len(content)`
and never consults the write's source class.

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
| Runtime dependencies (Go) | **none (Go standard library only)** | `go.mod` stays `require`-free; the Presidio backend (ADR-009) adds NO Go dependency — its third-party surface is the out-of-process Python sidecar |
| Runtime dependencies (Presidio sidecar, opt-in) | **pinned, base-only Python** (`presidio-analyzer`/`presidio-anonymizer` 2.2.362, spacy 3.8.14, en_core_web_lg 3.8.0) | only when `MEMGUARD_DETECTOR=presidio`; cleared `dep-scan` (all security checks pass, informational provenance WARN accepted); see ADR-009 + the Presidio section above |

---

## Audit emission configuration

Audit emission to the sibling **audit-trail** block is **opt-in and off by default** (ADR-007/ADR-014).
The `serve` daemon wires it from configuration:

| Source | Value | Default | Effect |
|--------|-------|---------|--------|
| `serve --audit-socket <path>` | path | — (absent) | Enables emission to the audit-trail emit socket at `<path>`. Absent/empty → emission disabled. The flag **wins** over the env fallback |
| `MEMGUARD_AUDIT_SOCKET` | path | — | Env fallback used only when `--audit-socket` is not given. Empty → disabled |

When a path resolves, `serve` wires `guard.WithAudit(buildAuditConfig(path))`, whose sink is an
`AuditTrailSink` (the confirmed plain-event wire contract, ADR-014) wrapped in `AsyncSink` (non-blocking
dispatch, so a stalled endpoint drops events rather than stalling the hot path). The `serve` startup
stderr line names the target: `audit: <path>` or `audit: off`. Emission is **fail-open**: a down, slow,
absent, or erroring audit-trail never blocks a verdict or surfaces an error (unlike the store/detector
factories, an unreachable audit path is **not** a construction error — it is a soft runtime dependency).

Below the CLI, emission is the same `AuditConfig` injected via `(*MemoryGuard).WithAudit`:

| Field | Type | Default | Effect |
|-------|------|---------|--------|
| `AuditConfig.Enabled` | bool | `false` | `false` → emission disabled. `true` enables emission only when `Sink` is also non-nil |
| `AuditConfig.Sink` | `AuditSink` | `nil` | The transport implementation (Unix socket via `AuditTrailSink`, or an in-process test sink). `nil` with `Enabled=true` fails closed to disabled (no emission, no crash) |

**Default:** emission is **disabled** (`AuditConfig{}` zero value; no `--audit-socket`, no env). Zero
connections are attempted until a path is configured.

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
