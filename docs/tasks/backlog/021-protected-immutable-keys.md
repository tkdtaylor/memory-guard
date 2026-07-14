# Task 021: Protected / immutable keys (write-time policy for identity/system memory slots)

**Project:** memory-guard
**Created:** 2026-07-14
**Status:** ❌ Not started

## Goal

Give `validate_write` a **named-key policy** so an operator (or memory-guard itself) can mark specific logical memory slots as **protected** (only an attested writer may set them) and/or **immutable** (a later write that changes an already-set value is detected). This closes a concrete instance of OWASP ASI06 memory poisoning that identity-scoped isolation (tasks 009/016) does not cover: isolation stops tenant B from reading or overwriting tenant A's entries, but says nothing about a single tenant's own **system-critical slots** (for example a stored persona/config value) being silently mutated by any writer who happens to hold that tenant's identity, or about a small set of **memory-guard's own** reserved slots that must never be forged or drifted regardless of who writes.

Two independent, composable behaviors, keyed off a new optional `key` argument on `validate_write`:

- **PROTECTED**: a write that targets a key matching a protected pattern from an unattested/absent writer is either **rejected** (the guard's own reserved namespace) or **flagged and allowed** (an operator-configured pattern). See the ownership-boundary decision below.
- **IMMUTABLE**: the guard keeps a SHA-256 baseline of the first value written under a given key. A later write under the **same** key whose (redacted) content hashes differently is **detected**, rejected for the reserved namespace, flagged and allowed for an operator-configured pattern.

## Context

- **Entries have no logical key today.** `entry` (`guard.go`) is `{content, boundIdentity, flags}`; the only identifier an entry has is the opaque `stored_id` (`"mem-"+randHex(6)`) the guard assigns at write time, the caller never supplies it and can never target an existing entry again. `key` in this task is a **new, separate, optional** concept: a caller-supplied logical slot name (for example `"memguard:detector-config"`, `"persona:system-prompt"`) that the guard uses **only** to run the policy checks below. It is **not** persisted on `entry`, not part of `MemoryStore`, and not readable back by key (no `ValidateReadByKey`). That keeps this task's surface to `guard.go` plus one new file, with zero `store.go` / `store_file.go` / data-model persisted-record impact.
- **Identity model reused, not extended.** Authorization is `Principal.Attested()` (`principal.go`, ADR-004, task 009), the same single attested/unattested bar `ValidateRead`'s isolation already enforces, no new identity concept, no per-key ACL/allowlist (see Out of scope). `SharedScope()` / `boundIdentity` (task 016, ADR-013) are an orthogonal axis (who may **read** an entry later) and are untouched by this task.
- **The SHA-256/deletion-hash idiom, reused.** `residue.go::deletionHash` is the precedent: a deterministic, namespaced SHA-256 hex digest over canonical inputs (`"delete\x00"+id+"\x00"+content`), stdlib-only (`crypto/sha256`), used for audit linkage. The immutable-key baseline uses the same idiom (`"immutable\x00"+content"`) for a different purpose: detecting drift, not linking a deletion.
- **KEY DECISION, who owns the protected-key policy (this task's ADR must record this explicitly):** memory-guard **enforces immutability of its own reserved identity/system keys, fail-closed**, because that is a correctness invariant of the guard's own state (the same posture the write-gate already takes on suspected poisoning), and **flags** protected/immutable violations on **operator-configured** keys, allowing the write through. The broad allow/redact/block **policy** for the general case (which patterns matter, what to do about a flagged write) stays **policy-engine's** job; memory-guard's contribution there is detection plus a stable flag, not enforcement. Concretely:

  | Key class | Protected check (write authorization) | Immutable check (value-change detection) |
  |---|---|---|
  | **Reserved system**: hard-coded prefix `memguard:` (`isReservedSystemKey`), always active, not configurable, cannot be disabled via env | unattested/absent writer: **REJECT** (`allow:false, stored_id:null`, flag `protected_key_violation`) | hash mismatch vs. the established baseline: **REJECT** (`allow:false, stored_id:null`, flag `immutable_mismatch`) |
  | **Operator-configured**: `KeyPolicy.Protected` / `KeyPolicy.Immutable` glob patterns, via `MEMGUARD_PROTECTED_KEYS` / `MEMGUARD_IMMUTABLE_KEYS` | unattested/absent writer: **FLAG, allow** (`allow:true`, flag `protected_key_violation`) | hash mismatch: **FLAG, allow** (`allow:true`, flag `immutable_mismatch`) |

  Reserved-key status takes precedence: a key matching both the reserved prefix and an operator pattern uses reserved (fail-closed) semantics only, never both a reject and a flag for the same violation.
- **Contract impact stays additive.** The tracer-validated `validate_write` response shape `{allow, stored_id, flags}` (ADR-008) is **unchanged**: `protected_key_violation` and `immutable_mismatch` are new **values** inside the existing `flags` array, exactly like `injection_suspected` / `pii:<LABEL>` today. The request gains one new **optional** sibling field to `entry`/`identity`: `"key"` (a plain string; absent/empty means today's unkeyed anonymous write, byte-identical behavior). No new top-level response field, no change to `validate_read` or `verify_delete`.
- **Backward compatibility is load-bearing.** `ValidateWrite(text string, identity map[string]any) map[string]any` is called directly by dozens of existing tests and by `main.go`'s `write`/`read` CLI demo. This task extends the signature with a **variadic** third parameter, `ValidateWrite(text string, identity map[string]any, key ...string) map[string]any`, mirroring the precedent `NewMemoryGuard(det Detector, store ...MemoryStore)` already uses for exactly this reason: every existing 2-arg call site compiles and behaves unchanged (`len(key) == 0` means the empty-key branch, which matches no protected/immutable pattern by construction and runs zero new logic).
- **Audit-trail emission is explicitly out of scope** (see Out of scope). This task adds no new `AuditSink` event builders; it only extends `ValidateWrite`'s existing flags/allow computation.
- Reference: [`docs/CONTRACT.md`](../../CONTRACT.md) (`validate_write` shape), [`docs/spec/data-model.md`](../../spec/data-model.md) (`entry`, the `flags` vocabulary), [`docs/spec/interfaces.md`](../../spec/interfaces.md) (the IPC wire shape), [`principal.go`](../../../principal.go) (`Principal`, `Attested()`, `principalFromMap`), [`residue.go`](../../../residue.go) (`deletionHash`, the SHA-256 idiom this task reuses), [`store_config.go`](../../../store_config.go) / [`detector_config.go`](../../../detector_config.go) (the config-factory pattern this task's `keys_config.go` mirrors).

## Requirements

| Req ID | Description | Priority |
|--------|-------------|----------|
| REQ-001 | **Reserved system keys, protected (fail-closed).** A write whose `key` starts with the hard-coded, non-configurable prefix `memguard:` from an unattested/absent principal is **rejected**: `{allow:false, stored_id:null, flags:[…,"protected_key_violation"]}`, nothing stored. The same write from an attested principal is allowed normally. | must have |
| REQ-002 | **Operator-configured protected keys, flag-only.** A write whose `key` matches a `KeyPolicy.Protected` glob pattern (sourced from `MEMGUARD_PROTECTED_KEYS`) from an unattested/absent principal is **allowed** (`allow:true`, `stored_id` set) but carries the `protected_key_violation` flag. From an attested principal, no such flag is added. | must have |
| REQ-003 | **Reserved system keys, immutable (fail-closed).** The first write under a reserved key (that clears REQ-001) establishes a SHA-256 baseline of the **redacted** content. A later write under the **same** key whose redacted content hashes differently is **rejected**: `{allow:false, stored_id:null, flags:[…,"immutable_mismatch"]}`, nothing stored (baseline unchanged). A later write with **identical** redacted content is allowed normally, every time. | must have |
| REQ-004 | **Operator-configured immutable keys, flag-only.** For a key matching a `KeyPolicy.Immutable` glob pattern (sourced from `MEMGUARD_IMMUTABLE_KEYS`), a hash mismatch against the established baseline is **allowed** (`allow:true`, `stored_id` set, entry persists) but carries the `immutable_mismatch` flag; the baseline is **not** overwritten by the mismatched value (it stays pinned to the first-seen hash, so drift is detectable on every subsequent write, not just the first one). | must have |
| REQ-005 | **Backward compatibility.** `ValidateWrite`'s existing 2-arg call sites (`g.ValidateWrite(text, identity)`) compile and behave byte-identically (the omitted variadic `key` defaults to `""`, which matches no reserved or configured pattern). The full pre-existing suite (`guard_test.go`, `poisoning_suite_test.go`, `identity_isolation_test.go`, `identity_durable_test.go`, `audit_test.go`, `contract_tracer_test.go`, `residue_test.go`, `residue_indexes_test.go`, detector suites) passes **unmodified**. | must have |
| REQ-006 | **Config factory.** `NewKeyPolicyFromConfig(protectedCSV, immutableCSV string) (KeyPolicy, error)` parses comma-separated glob-pattern lists (`path.Match` syntax) for both knobs, mirroring `NewStoreFromConfig`/`NewDetectorFromConfig`'s fail-closed construction-error pattern: a malformed pattern is a construction error (`path.ErrBadPattern`), never a silently-dropped pattern. An empty/absent value on either knob yields an empty pattern list for that knob (only the always-on reserved namespace is active); `main.go` wires `MEMGUARD_PROTECTED_KEYS` / `MEMGUARD_IMMUTABLE_KEYS` through it into `serve`'s guard via a new `WithKeyPolicy` builder (mirroring `WithAudit`; the two builders must compose in either call order, each preserving the other's already-set field when copying the guard). | must have |
| REQ-007 | **Baseline hash is genuinely mutation-sensitive.** The immutable-baseline hash function (`immutableBaselineHash`, namespaced SHA-256 over the redacted content, same idiom as `deletionHash`) is proven, by a dedicated test, not inferred from the happy path, to change when a **single byte** of content changes, and to be stable (same digest) across repeated calls on identical content. | must have |
| REQ-008 | **Contract/spec parity.** The tracer-validated `validate_write` response shape `{allow, stored_id, flags}` is unchanged (no field added/removed/retyped) even when a key-policy flag fires, verified against the live/decoded JSON, not just the Go map. `docs/CONTRACT.md`, `docs/spec/interfaces.md` (new `key` request field plus the two new flag values and the two new env vars), `docs/spec/data-model.md` (flag vocabulary plus the in-process baseline registry and its durability limitation), `docs/spec/behaviors.md` (the new write-time policy behavior), and `docs/spec/configuration.md` (`MEMGUARD_PROTECTED_KEYS` / `MEMGUARD_IMMUTABLE_KEYS`) are updated in the same commit. A new ADR (number assigned at execution time) records the two-tier ownership boundary (reserved-fail-closed vs. configured-flag-only, deferring the broader allow/redact/block policy to policy-engine) and the immutable-baseline **durability limitation** (the baseline registry is in-process only in this task, lost on restart; mirrors task 009's identity model before task 016 made it durable; explicitly flagged as future work, not silently assumed). | must have |
| REQ-009 | **Substrate constraints.** Stdlib-only (`path.Match`, `crypto/sha256`; `go.mod` stays require-free). `make fitness` green, no detector/store/identity backend specifics leak past their seams (`keys.go`/`keys_config.go` introduce no new seam-banned tokens). IPC error shape (`{error:{code,message,retryable}}`) untouched. The existing write-gate ordering is preserved: injection detection still runs **first** and is unaffected by key policy (a write that trips both `injection_suspected` and a key-policy violation is rejected via the existing injection path; key-policy checks never run on an already-rejected write). | must have |

## Readiness gate

- [ ] Test spec `021-protected-immutable-keys-test-spec.md` exists in `docs/tasks/test-specs/`
- [ ] Confirm no external consumer calls `MemoryGuard.ValidateWrite` outside this repo (the variadic signature change is source-compatible for in-repo Go call sites; any out-of-repo binding would need re-generation; in-repo only today, per `AGENTS.md`'s reusability note)
- [ ] Decide (and record in the ADR) whether `write`/`read` CLI demo subcommands gain `key` support. **Default answer: no**, they stay unkeyed one-shot demos; only the IPC `serve` path exercises `key` in this task

## Acceptance criteria

- [ ] [REQ-001] Reserved key `memguard:*`, unattested/absent writer → rejected with `protected_key_violation`, nothing stored (TC-001). Attested writer → allowed (TC-002).
- [ ] [REQ-002] Operator-configured protected key, unattested/absent writer → allowed + flagged (TC-003). Attested writer → allowed, no flag (TC-004).
- [ ] [REQ-003] Reserved key, second write with different (redacted) content → rejected with `immutable_mismatch` (TC-005). Second write with identical content → allowed, no flag, every time (TC-006).
- [ ] [REQ-004] Operator-configured immutable key, second write with different content → allowed + flagged, both entries persist with distinct `stored_id`, baseline stays pinned to the first value (TC-007).
- [ ] [REQ-005] 2-arg `ValidateWrite` call sites unaffected; full pre-existing suite green, unmodified (TC-008).
- [ ] [REQ-006] `NewKeyPolicyFromConfig` parses valid CSV glob lists, fails closed on a malformed pattern, empty input yields an empty (reserved-only) policy; `WithKeyPolicy`/`WithAudit` compose in either order (TC-009).
- [ ] [REQ-007] `immutableBaselineHash` changes on a single-byte content change and is stable on identical content, verified directly (not inferred) (TC-010).
- [ ] [REQ-008] `validate_write` response decodes to the exact key set `{allow, stored_id, flags}` in every key-policy branch; ADR plus all five spec files updated in the same commit (TC-011, TC-012).
- [ ] [REQ-009] Injection detection still runs first and is unaffected by key policy; `make fitness` green; `go.mod` require-free (TC-012, TC-013).
- [ ] `go build ./... && go test ./...` green; `make check` green.

## Verification plan

- **Highest level achievable: L6**, operator-observed over the live socket: `MEMGUARD_PROTECTED_KEYS=config:* MEMGUARD_IMMUTABLE_KEYS=baseline:* go run . serve --socket /tmp/mg-021.sock`. Via `nc -U /tmp/mg-021.sock`:
  1. `validate_write` reserved key `memguard:policy`, no identity → `{"allow":false,"stored_id":null,"flags":["protected_key_violation"]}`.
  2. `validate_write` reserved key `memguard:policy`, attested identity → `{"allow":true,"stored_id":"mem-…","flags":[]}`.
  3. `validate_write` reserved key `memguard:policy`, attested identity, **different content** → `{"allow":false,"stored_id":null,"flags":["immutable_mismatch"]}`.
  4. `validate_write` configured-protected key `config:threshold`, no identity → `{"allow":true,"stored_id":"mem-…","flags":["protected_key_violation"]}`.
  5. `validate_write` configured-immutable key `baseline:limit` twice with different content, attested → both `allow:true`, second response's `flags` contains `immutable_mismatch`, two distinct `stored_id`s.
     Quote all five response lines verbatim.
- **Level 2 (unit):** `go test ./...` → `ok`, including the full pre-existing suite unmodified and the new `keys_test.go` / `keys_config_test.go` / extended `guard_test.go` cases.
- **Level 3 (gate):** `make fitness` and `make check` exit 0 (seam gate confirms no new backend token leaked into `guard.go`/`ipc.go`/`main.go`).
- **Level 5 (validation harness):** a socket-level test (mirroring `contract_tracer_test.go`'s pattern) drives the reserved-reject, reserved-immutable-reject, configured-flag, and configured-immutable-flag cases over a real `serve` socket, decoding each JSON response and asserting the exact key set `{allow, stored_id, flags}` plus the flag values field-by-field (not a smoke check). Record the final assertion line in the verify commit.

## Out of scope

- **Reading an entry back by `key`** (a `ValidateReadByKey` verb or a store-side key index): `key` is a write-time policy input only in this task, not a new lookup path. A future task could add it.
- **Persisting the immutable-baseline registry** across a restart (`FileStore`/`store_file.go`): stays in-process for this task, explicitly flagged as a durability limitation in the ADR (mirrors the 009-to-016 precedent for identity durability).
- **Fine-grained per-key ACLs / allowlists of specific authorized subjects**: authorization is the single existing `Attested()` bar, matching the granularity `ValidateRead`'s isolation already uses. A named-allowlist-per-pattern extension is a future contract decision with its own ADR.
- **Audit-trail emission of key-policy events**: no new `AuditSink` event builder is added; the existing PII-redaction/injection-rejection emission is unaffected. A future task can extend `audit.go` symmetrically once this task's flags are stable.
- **CLI (`write`/`read` subcommand) support for `--key`**: the one-shot demo commands stay unkeyed; only the IPC `serve` path exercises `key` (see Readiness gate).
- **Glob-pattern richness beyond `path.Match`** (regex patterns, prefix-only shortcuts): `path.Match`'s stdlib syntax (`*`, `?`, `[...]`) is sufficient for v1; a richer pattern language is a future ask.

## Dependencies

- **Depends on:** completed task 009 (`Principal` seam, `Attested()`, `principalFromMap`) for authorization; completed task 003 (the SHA-256/`deletionHash` idiom `residue.go` establishes) as the precedent this task's `immutableBaselineHash` reuses.
- **Blocks:** nothing in the current backlog; a future policy-engine task that consumes `protected_key_violation`/`immutable_mismatch` flags to decide broader allow/redact/block behavior builds on this task's flag vocabulary.
- **Independent of** the audit-trail tasks (010/017) and task 016's durable identity work: no shared files beyond `guard.go` and the spec docs; safe to sequence either way.
</content>
