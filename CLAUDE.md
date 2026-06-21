# memory-guard — Claude Code layer

@AGENTS.md

The shared, harness-neutral briefing above (imported from `AGENTS.md`) is the
canonical source of truth: project context, invariants, commands, the task workflow,
verification ladder, commit rules, boundaries, and the load-bearing process rules.
**Read it first.** This file adds only the parts specific to Claude Code.

## Recommended tooling — Claude Code

### Skills
- **code-scanner** — scan any target repo/package/deps for malware before adopting or
  running them; wire into the verification gate as a blocking step. Trigger: "scan this
  repo for malware".
- **code-review** — review the agent's diffs before merge, especially anything touching
  the `Detector` seam, the write-gate, or `verify_delete`. Trigger: `/code-review`.
- **deep-research** — when designing a new detector backend or evaluating Presidio
  vs. ONNX vs. native, survey prior art / build-vs-adopt. Trigger: "deep research on
  <X>".

### Subagents (`.claude/agents/`)
- **task-executor** — implement a single task from its file + test spec. Invoke:
  `use task-executor — task: docs/tasks/backlog/NNN-name.md, spec: docs/tasks/test-specs/NNN-name-test-spec.md`
- **spec-verifier** — assertion-by-assertion APPROVE/BLOCK gate before promoting a task
  to ✅. Invoke: "use the spec-verifier on task NNN".
- **security-auditor** — security pass on any change to the write-gate or detector
  before ship. Invoke: "use the security-auditor on the write-gate". It checks for
  poisoning that bypasses the gate, PII that reaches the store, and detector specifics
  leaking past the seam.

These role prompts are also the source the Codex/Gemini harnesses mirror manually;
under Claude Code they are dispatchable subagents.

## Plan mode

When you exit plan mode, a hook restructures the plan: each step becomes a task file in
`docs/tasks/backlog/`, test-spec stubs are created, and the full plan is backed up to
`docs/plans/`. Use the **task-executor** agent to work through tasks one at a time.

### End handoffs with a resume command

When a response completes a milestone that leaves follow-on work, end with a **fenced
code block** containing the exact resume command. Verify the path exists before writing
it (glob `docs/tasks/backlog/NNN-*.md` and the matching test-spec). Skip the block when
there is genuinely nothing to resume.

## Hook profiles

Hooks run automatically and are gated by profile level. Control via environment
variables:

```bash
export CLAUDE_HOOK_PROFILE=minimal    # Safety hooks only (secret protection, block-no-verify, config-protection, protect-checkout)
export CLAUDE_HOOK_PROFILE=standard   # + workflow hooks (plan restructuring, compaction, checkpoints) — default
export CLAUDE_HOOK_PROFILE=strict     # + formatting, fitness, notifications
export CLAUDE_DISABLED_HOOKS=desktop-notify,batch-format-typecheck  # Disable specific hooks
```

Wired via `.claude/settings.json` (standard profile): `no-commit-on-main`,
`protect-secrets`, `block-no-verify`, plan→tasks restructuring, compaction guards,
spec-coverage-check.

## inject-retros mechanism

The `inject-retros.py` SessionStart hook reads the retro log from `AGENTS.md`,
`CLAUDE.md`, and `docs/agent-rules.md` and surfaces relevant entries at the start of
every session — so adding an entry to `docs/agent-rules.md` is how a one-time mistake
becomes a permanent guard for the Claude Code session. The *essentials* are already
inlined in `AGENTS.md` so they reach every harness even without this hook.
