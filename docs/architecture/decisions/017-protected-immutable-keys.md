# ADR-017: Protected / immutable keys (write-time named-key policy)

**Status:** Accepted
**Date:** 2026-07-14
**Task:** [021 (Protected / immutable keys)](../../tasks/completed/021-protected-immutable-keys.md)
**Relates to:** ADR-004 (the `Principal` seam and `Attested()` bar this task's authorization reuses, no new identity concept), ADR-003 (the namespaced-SHA-256 `deletionHash` idiom the immutable baseline reuses), ADR-008 (the tracer-validated `validate_write` response shape this ADR leaves byte-identical), ADR-012 (the fail-closed config-factory pattern `keys_config.go` mirrors), ADR-013/ADR-015/ADR-016 (the optional identity-map fields and the `WithAudit`/`WithWriteInspector` builder pattern `WithKeyPolicy` composes with).

## Context

Identity-scoped isolation (tasks 009/016, ADR-004/ADR-013) stops tenant B from reading or overwriting tenant A's entries. It says nothing about a single tenant's own **system-critical slots** (a stored persona, a config value) being silently mutated by any writer who happens to hold that tenant's identity, nor about a small set of **memory-guard's own** reserved slots that must never be forged or drifted regardless of who writes. That is a distinct instance of OWASP ASI06 memory poisoning: not a cross-tenant leak, but the drift of a named, system-critical value over time.

An entry has no logical key today. The only identifier is the opaque `stored_id` the guard mints at write time; a caller can never target an existing entry again. So a policy that keys off a logical slot name needs a new, optional, caller-supplied `key` argument on `validate_write`, used only to run the policy checks.

Two questions had to be answered: **who owns the policy** (does memory-guard enforce, or only detect and flag?), and **how durable is the baseline** that immutability is checked against.

## Decision

**Add an optional variadic `key` to `validate_write` and a two-tier named-key policy: memory-guard enforces its own reserved `memguard:` namespace fail-closed, and flags (allows through) operator-configured pattern violations. The immutable baseline is a namespaced SHA-256 over the redacted content, held in an in-process registry. The tracer-validated `{allow, stored_id, flags}` shape is unchanged: `protected_key_violation` and `immutable_mismatch` are new additive flag values only.**

### 1. Two-tier ownership: reserved fail-closed, configured flag-only

| Key class | Protected check (write authorization) | Immutable check (value-change detection) |
|---|---|---|
| **Reserved system**: hard-coded prefix `memguard:` (`isReservedSystemKey`), always active, not configurable, cannot be disabled via env | unattested/absent writer: **REJECT** (`allow:false, stored_id:null`, flag `protected_key_violation`) | hash mismatch vs. the established baseline: **REJECT** (`allow:false, stored_id:null`, flag `immutable_mismatch`) |
| **Operator-configured**: `KeyPolicy.Protected` / `KeyPolicy.Immutable` globs, via `MEMGUARD_PROTECTED_KEYS` / `MEMGUARD_IMMUTABLE_KEYS` | unattested/absent writer: **FLAG, allow** (`allow:true`, flag `protected_key_violation`) | hash mismatch: **FLAG, allow** (`allow:true`, flag `immutable_mismatch`, baseline stays pinned) |

memory-guard enforces immutability of its **own** reserved identity/system keys fail-closed, because that is a correctness invariant of the guard's own state (the same posture the write-gate takes on suspected poisoning). For **operator-configured** keys it contributes detection plus a stable flag, not enforcement. The broader allow/redact/block policy for the general case (which patterns matter, what to do about a flagged write) stays **policy-engine's** job. Reserved-key status takes precedence: a key matching both the reserved prefix and an operator pattern uses reserved (fail-closed) semantics only, never both a reject and a flag for one violation.

Authorization is the existing `Principal.Attested()` bar only (ADR-004). No new identity concept, no per-key ACL or named allowlist. Reserved-prefix matching is a `strings.HasPrefix` prefix match, not a substring match, so `user-memguard:note` is not reserved.

### 2. The immutable baseline: namespaced SHA-256 over redacted content

`immutableBaselineHash(content) = hex(SHA-256("immutable\x00" + content))`, the same idiom as `residue.go::deletionHash` (`"delete\x00" + id + "\x00" + content`), a deterministic namespaced digest over canonical bytes, stdlib-only (`crypto/sha256`), for a different purpose: detecting drift, not linking a deletion. The `"immutable\x00"` prefix keeps the two digest spaces disjoint. The hash is over the **redacted** content (what actually persists), verbatim with no normalization, so a single-byte change yields a different digest; the mutation-sensitivity is the whole point and is proven directly by a dedicated test, not inferred from a happy path.

The first accepted write under a key establishes its baseline. A later mismatch never overwrites it, so the baseline stays pinned to the first-seen value and drift is detectable on every subsequent write, not just the first. A write rejected by the protected check establishes no baseline.

### 3. Contract stays additive; the key is not persisted

The `validate_write` request gains one optional sibling field to `entry`/`identity`: `key` (a plain string; absent/empty = today's unkeyed write, byte-identical). `protected_key_violation` and `immutable_mismatch` are new **values** inside the existing `flags` array, exactly like `injection_suspected` / `pii:<LABEL>`. No new top-level response field; `validate_read` / `verify_delete` are untouched. The `key` is a write-time policy input only: it is not persisted on `entry`, not part of `MemoryStore`, and not readable back by key (no `ValidateReadByKey`).

`ValidateWrite` extends **variadically** (`ValidateWrite(text, identity, key ...string)`), mirroring `NewMemoryGuard(det, store ...MemoryStore)`. Every pre-021 2-arg call site compiles and behaves byte-identically (`len(key) == 0` means the empty-key branch, which matches no pattern and runs zero policy logic).

### 4. Ordering: injection first, key policy second

Injection detection still runs **first** and is unaffected. Key-policy checks run only on the accepted path, after the injection gate, so a write that trips both `injection_suspected` and a key violation is rejected via the existing injection path and never reaches the key policy (and establishes no baseline). This preserves the fail-closed write-gate invariant unchanged.

### 5. Config factory + builder composition

`NewKeyPolicyFromConfig(protectedCSV, immutableCSV) (KeyPolicy, error)` parses comma-separated `path.Match` glob lists, mirroring `NewStoreFromConfig`/`NewDetectorFromConfig`'s fail-closed construction: a malformed pattern is a construction error wrapping `path.ErrBadPattern` (matchable with `errors.Is`), never a silently-dropped pattern. Empty input yields an empty (reserved-only) policy. `main.go` wires the two env vars through it into `serve`'s guard via a new `WithKeyPolicy` builder that mirrors `WithAudit`. `WithKeyPolicy`, `WithAudit`, and `WithWriteInspector` (task 018) each preserve the others' already-set fields when they copy the guard, so they compose in any call order.

## Consequences

- A concrete ASI06 drift vector (silent mutation of a system-critical named slot) is now detectable, and memory-guard's own reserved slots are fail-closed protected against forge and drift.
- The reserved namespace is active even without any operator configuration, so the guard's own invariant does not depend on deployment config.
- **Durability limitation (explicit future work, not silently assumed):** the immutable-baseline registry is **in-process only** in this task. It is lost on restart, so a reserved/immutable key's baseline resets to the first post-restart write. This mirrors task 009's identity model before task 016 made it durable. Persisting the registry (alongside `FileStore`) is deferred to a future task; the two-tier ownership boundary and the flag vocabulary are stable, so that extension is additive.
- **Growth-bound note (security-auditor SEC-001, low severity, non-blocking):** the baseline registry also has no size cap or eviction. A writer spraying distinct keys under an operator-configured immutable glob (the immutable check runs for any writer on the flag-only tier) grows the map one entry per first-seen key. The attack surface is the local `0600` socket and the growth is bounded below the store's own unbounded growth, so it is a documented limitation, not a live exploit. A cap/eviction is folded into the same future task that persists the registry. Separately, the reserved-key fail-closed guarantee is exactly as strong as the socket's upstream attestation claim (`PreVerifiedPrincipal` trusts the wire `trust_tier`, ADR-004): no weaker, no stronger, unchanged by this task.
- **Deferred (out of scope, each a future ADR if taken up):** reading an entry back by `key`; fine-grained per-key ACLs / named allowlists beyond the single `Attested()` bar; audit-trail emission of key-policy events; glob richness beyond `path.Match`; CLI `--key` support on the `write`/`read` demo subcommands (only the IPC `serve` path exercises `key`).
