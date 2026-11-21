# Project Rules & Coding Guidelines (hsync-rendezvous — Python + C)

This document defines the strict architectural, development, and code-reuse rules
for the `hsync-rendezvous` repository. You and any coding agent must strictly adhere to these
guidelines at all times.

> **Where this file comes from**: portable, self-contained copy of the rules for
> this repository. The canonical single source of truth for the HSYNC monorepo is
> the root `AGENTS.md` (which also drives `.clinerules/` via
> `scripts/dev/gen-clinerules.py`). Keep project-specific rules here; edit the
> root `AGENTS.md` for anything shared.

`hsync-rendezvous` is a **multi-language repository**: one wire protocol
(`rdv/1`) with several implementations of the *same* contract
(`python/` today, `c/` next). This file mirrors the
Python project guidelines used by the other HSYNC projects and adds the rules
that apply to the C implementation.

---

## 🗂️ Repository Layout & Git Rules

| Path | Content |
|---|---|
| `protocol-spec/rdv-1.md` | Wire-protocol specification — the **single source of truth (SSOT)** |
| `fixtures/rendezvous-*.json` | Shared protocol fixtures (single source for every language) |
| `tests/` | **Language-neutral** black-box suite (spawns the binary, wire-only) |
| `bench/` | L1/L2/L3 benchmarks; L2/L3 are language-neutral |
| `python/` | Python + aioquic implementation (v1) and its white-box unit suite |
| `c/` | C11 implementation of the same contract (planned, v2) |
| `packaging/` | OS service units (`systemd`/`launchd`/`windows`) and the `.deb` payload |
| `compile.sh` | Root build entry point (`native`/`rpi`/`deb`/`deb-all`, `-l/--language`) |
| `llm-wiki/` | Internal agent knowledge base |
| `docs/` | End-user documentation |

* **One commit per repository**: `hsync-rendezvous` is its own git repository.
  Verify it before any git command with
  `git -C hsync-rendezvous rev-parse --git-dir`; if the check fails, **stop and
  report it as a blocker** — never `git init`, never commit these files from
  another repository.
* Inspect what you are about to commit (`git -C hsync-rendezvous status --short`
  and `git diff --cached`) and prefer explicit paths over `git add -A`.
* **Never stage build outputs or secrets**: `dist/`, `build/`, `*.deb`,
  `*.o`/`*.a`/`*.so`, `*.env`, and any local `group-keys` file.
* Each implementation is compiled by the build script inside **its own**
  directory (`python/compile.sh`, and `c/compile.sh` once the port lands);
  `compile.sh` at the root only *dispatches* and assembles artifacts
  (native/rpi/deb/deb-all).

---

## 📚 Documentation Maintenance (Dual-Docs System)

The project maintains two distinct documentation environments. You must understand the difference and maintain both appropriately:
1. **`llm-wiki/` (Internal/Agent Knowledge Base)**: An agent-readable, structured map of the application's architecture, logic, and internal code references.
2. **`docs/` (End-User Technical Documentation)**: Human-readable documentation, user guides, and public API references meant for the final user.

### 1. Docs-First Workflow (Mandatory)
* **Read Before Exploring or Modifying Code**: Before exploring or modifying application code, you **MUST** first consult the internal wiki, starting from `llm-wiki/README.md`, and then drill down into the specific `llm-wiki/` file(s) relevant to the task. Administrative, repository-inspection, and documentation-only operations may use a proportionate subset of this workflow.
* **Index-Driven Navigation**: Use `llm-wiki/README.md` as the map: identify which module/feature/data-model docs are relevant, read them, and follow their `path/to/file.py::symbol` (Python) / `path/to/file.c::symbol` (C) references to reach the right code directly instead of blindly searching the whole repository.
* **Docs Guide the Search**: Treat `llm-wiki/` as the first search surface. Codebase-wide exploration is a **fallback** for what the wiki does not yet cover. Remember that `llm-wiki/README.md` also lists the **hard invariants** (no-log, RAM-only, rigid schema, protected buckets, zero backward compatibility) that must be read before touching any module.
* **Rendezvous on Absence**: If a specific doc does not exist or lacks relevant content, note the gap and create/extend it as part of the task. A missing doc is never an excuse to skip the docs-first step.

### 2. Mandatory Dual-Synchronization
* **Code & Docs Are One Change**: Whenever you **add, modify, or remove** any relevant element of the application, you **MUST** update the documentation **within the same task**.
* **Assess the Impact (The Dual Update)**:
  * *Internal Changes* (Refactoring, internal schemas, private logic): You must update the relevant files in **`llm-wiki/`**.
  * *User-Facing Changes* (Public APIs, CLI commands, features, configuration files): You must update the internal architecture in **`llm-wiki/`** AND the user guides/technical specs in **`docs/`**.
* **No Stale Docs**: Leaving either `llm-wiki/` or `docs/` out of sync with the code is **STRICTLY PROHIBITED**. If you cannot fully document a change in both places, the task is **not complete**.
* **Semantic Changes Only**: Update documentation when the documented architecture, behavior, contract, configuration, or operational procedure changes. Pure formatting, behavior-preserving refactoring, and test-only changes do not require documentation churn unless they reveal that existing documentation is inaccurate.

### 3. Directory Structures
Both doc sets are versioned with their project and committed in the same change
as the code they describe: `llm-wiki/` and `AGENTS.md` included, so a project's
`.gitignore` must not exclude them.

Both follow a recommended **baseline** layout; adapt the exact file set
to the project's nature (multi-language network daemon) and keep each index
`README.md` honest about what actually exists.
* **LLM-Wiki (`llm-wiki/`) - Agent Optimized** (baseline):
  * `llm-wiki/README.md` — index / table of contents linking every other doc, plus the hard invariants.
  * `llm-wiki/architecture.md` — high-level system overview and component interactions.
  * `llm-wiki/modules/<module>.md` — internal responsibilities, key functions (add, rename, split or omit as the project requires; a doc is justified only when it maps to real code).
  * `llm-wiki/data-models.md` — the `rdv/1` frame models of every implementation and their relationships (pydantic models in `python/`, structs/unions in `c/`); add it as soon as the models are worth mapping.
  * `llm-wiki/decisions.md` — log of design decisions (already present; keep the numbering stable).
* **User Docs (`docs/`) - Human Optimized** (only the subset that applies):
  * `docs/README.md` — welcome page, installation, and quickstart for the user.
  * `docs/usage.md` — how to use the software (CLI reference, group keys, OS services).
  * Add domain-appropriate guides when relevant (e.g. `docs/api.md` only when a public HTTP API exists) and omit what does not apply.

### 4. Content & Style Rules
* **For `llm-wiki/` (Concise & Factual)**: Write for an LLM consumer. Use bullet lists, tables, and clear headings. Avoid duplication. Reference the relevant source location using the `path/to/file.py::symbol` / `path/to/file.rs::symbol` pattern (`::` followed by the exact function/class/constant/module-level name; methods qualify their owner, e.g. `file.py::Class.method`). **Never use line numbers** (`file.py:123`): they drift on every edit. Do not duplicate large code blocks; describe intent and point to the code.
* **For `docs/` (Clear & Explanatory)**: Write for a human developer/user. Provide context, practical examples, and clear step-by-step guides. Do NOT expose internal routing or private function names here; focus on the public interface.
* **Keep the Indexes Honest**: When you add, rename, or delete a doc file in either directory, update the respective `README.md` in the same change.

### 5. User-Docs Authoring Framework (`docs/` only)

When creating or modifying end-user documentation, apply these standard
documentation-engineering rules:

* **Diátaxis roles — one dominant role per file**: every `docs/` file has a
  single dominant role:
  * *Tutorial / Chooser* — a short landing page that picks the path and links
    to what to do next; it never embeds full procedures.
  * *How-To* — a task procedure with concrete, copy-paste commands for **one
    environment only** (no mixed native/Docker or Linux/macOS/Windows blocks in
    the same code fence).
  * *Reference* — command/option/env-var/table listings; the single source of
    truth for syntax and defaults (`docs/usage.md` today).
  * *Explanation* — concepts, flows, and why-things-work; it may link to a
    How-To but must NOT embed or restate its procedures.
  Do not write "hybrid" pages (e.g. a reference that contains a full tutorial,
  or a concept guide that duplicates the quick start).
* **Single-source-of-truth (SSOT)**: every command, option, or procedure is
  documented exactly once. Quick-start procedures live only in the dedicated
  getting-started pages; concept/usage pages link to them instead of repeating
  them. Index/splitter pages are links only — no content that can drift from the
  page they point to.
* **Task-based / outcomes-first**: organise content by user goal ("Install",
  "Run the node", "Protected buckets", "Deploy as a service", "Troubleshoot"),
  and structure the docs `README.md` as a linear journey (Install → run →
  configure → operate → understand → reference). Never organise by internal
  module names.
* **One environment per page**: when a procedure differs by installation or
  run mode (`.deb`, from source, Docker, per-OS service), split it into separate
  self-contained pages; a single code fence must contain commands for only one
  environment.
* **Link integrity, atomically**: when adding, renaming, moving, or removing
  sections, update every affected intra-doc anchor, every inter-repo link, and
  the docs index in the same change.

### 6. Removal Discipline
* **Delete With the Code**: When a feature or logic is **removed**, delete or update its documentation in BOTH `llm-wiki/` and `docs/` in the same change. Consistent with the project's *Zero Backward Compatibility* stance, do **NOT** keep documentation describing removed functionality.

### 7. Drift Prevention (Reference Integrity)

The wiki must describe the code as it is **now**. Accumulated inaccuracies come from restating facts that the code already owns, so:

* **Reference, never restate, derivable facts.** Point to `path/to/file::symbol` instead of copying values the symbol owns: versions, defaults, thresholds, counts, route paths, CLI flags, enum members, table/column names, and config keys. Write "the version SSOT (`…::VERSION`)" rather than the literal value. A quoted value is acceptable only when it is the point of the sentence (e.g. a limit a reader must know); it must name its owning constant and be updated with it.
* **No history on current-state pages.** `architecture.md`, `data-models.md` and `modules/*` describe the present. Measurements and "was X, now Y" belong in a dated benchmark page or an ADR; delete prose that no longer explains current behavior.
* **Historical mentions must be explicit.** A sentence about removed code is allowed only with an explicit historical marker (e.g. "the old `x.py` shim was removed"); otherwise delete it with the code.
* **Unambiguous cross-repo references.** Use a repository-relative link or a fully qualified `repo/path::symbol`; a bare sibling path (e.g. `hsync_client/p2p.py`) becomes ambiguous as soon as either repository renames the module.
* **One responsibility per page.** Split a page when it describes areas that change independently, so a code change touches the smallest possible doc surface.
* **Verify reference integrity before completion.** Every `path::symbol` must resolve (file exists, declaration exists), every backticked path and markdown link/anchor must exist, and every quoted derived value must match its owning symbol. Correct or delete stale references in the same task: an unresolved reference is a task defect, not a follow-up.

---

## ⚠️ Domain-Critical Rules

* **Wire protocol — single source of truth**
  `protocol-spec/rdv-1.md` is the SSOT for the `rdv/1` wire protocol, shared by
  **every** implementation. Before modifying any frame, field, ALPN, framing rule
  or refusal semantic you **MUST** read it and follow it. **Never fork the spec**
  into `python/` or `c/`: the same frames must be byte-identical across
  languages.

* **Shared fixtures**
  `fixtures/rendezvous-*.json` are the shared protocol fixtures: the same bytes
  must validate every implementation. Any protocol change updates the spec, the
  fixtures, every implementation, the drift/parity tests and the docs
  **atomically**.

* **Language-neutral black-box suite**
  `tests/` at the repository root is the *contract* test suite. It spawns the
  binary resolved from `HSYNC_RENDEZVOUS_BIN` and observes only the public CLI and
  the `rdv/1` wire protocol: it **never** imports `hsync_rendezvous` (or any C
  object) and never touches internal state. The identical suite must pass against
  `python/` and `c/`. Frame builders live in `tests/harness.py` (single
  source, language-neutral) — do not duplicate them inside an implementation
  directory. Readiness is signalled through the `HSYNC_RENDEZVOUS_READY_FILE`
  seam; the suite is gated by `HSYNC_BB_RENDEZVOUS=1`.

* **No-log invariant**
  Identical in every language: the process NEVER writes peer data (IPs, CIDs,
  timestamps) to disk. The routing table is RAM-only; the TLS identity is a
  persistent ECDSA P-256 key+cert kept **by default** (`--identity PATH`
  overrides the XDG state path; `--ephemeral` keeps it in memory) — the
  operator's own key+cert (ADR-0034/ADR-0037), never peer data, so the
  fingerprint is stable and rotatable; diagnostics are
  stderr-only and split in two: an always-on, peer-free operational channel
  (`warn`/`error`) and the opt-in, peer-aware full operation log (`--debug` /
  `HSYNC_RENDEZVOUS_DEBUG=1`). Enforced for
  Python by `python/tests/test_nolog.py` (read-only filesystem sandbox): the C
  port must ship an equivalent enforcement test.

* **Rigid schema**
  Every `rdv/1` frame model rejects unknown fields (pydantic
  `extra="forbid"` in Python; an explicit unknown-field rejection in C). Unknown or targeted fields make the frame invalid and it is silently
  dropped — never reinterpreted, never partially applied.

* **Protected buckets**
  Tokens are derived as `HMAC-SHA256(key, "rdv/1" || bucket)[:32]` hex and
  compared in constant time; refusals are uniform (`token_required`) and never
  reveal whether a bucket exists. Group keys enter the process **only** through
  `--keys-fd` / `HSYNC_RENDEZVOUS_KEYS_FD` (a file descriptor, never a path inside
  the sandbox) and are read once at startup. Rate limits are in-memory sliding
  windows; `HSYNC_RENDEZVOUS_NO_RATE_LIMIT` is a test/benchmark seam that must
  never be documented as a production option.

* **Packaging — synchronous updates are mandatory**
  Any change to CLI flags, environment variables (`HSYNC_RENDEZVOUS_*`), option
  defaults or user-facing behavior **REQUIRES** an atomic update to:
  * the implementation CLI (`python/src/hsync_rendezvous/cli.py`, and `c/` once
    the port lands);
  * the man page `packaging/deb/usr/share/man/man1/hsync-rendezvous.1`
    (OPTIONS, ENVIRONMENT, FILES, EXAMPLES, `.TH` date/version);
  * the `.deb` payload under `packaging/deb/` and the language dispatch points in
    `compile.sh` (`validate_language`, `_build_native`, `_build_onedir`,
    `_container_native_cmd`, `_container_build_cmd`);
  * the OS service units `packaging/{systemd,launchd,windows}/`;
  * `README.md` and `docs/usage.md`;
  * the language-neutral suite `tests/` when the observable CLI/exit-code
    contract changes.

  A new language port also requires its own per-language binary script (e.g.
  `c/compile.sh`) and must be wired into `compile.sh`; the root script must
  keep failing fast for languages that do not exist yet.

---

## 🚀 Evolution & Breaking Changes

* **Zero Backward Compatibility**
  There are no existing production environments. **Backward compatibility is NOT required when the requested design intentionally changes a contract.** Prioritize the ideal architecture and optimal design over supporting legacy states, but do not introduce unrelated breaking changes. Update all affected callers, models, tests, configuration, persisted assumptions, protocol artifacts, consumers, packaging, and documentation atomically.

* **Clean Breaking Changes**
  Treat every major intervention as a completely new version of the application. Implement rigid contracts, mandatory protocol versions, and strict data fields. **CATEGORICALLY REMOVE** shims, legacy channels, migration phases, and fallback logic.

* **Multi-language obligation**
  Breaking the wire contract means bumping the mandatory `protocol_version`
  (`rdv/1` → `rdv/next`) and updating **atomically**: `protocol-spec/rdv-1.md`
  (or its successor), `fixtures/`, `python/`, `c/`, `tests/`, `bench/`,
  `compile.sh`/`packaging/`, `llm-wiki/` and `docs/`. No implementation may
  keep speaking the retired version, and no compatibility shim may exist in one
  language only.

---

## ✅ Implementation Quality Gate

Every code change must pass a bounded implementation and verification cycle before the task may be considered complete.

### 1. Acceptance Criteria Before Implementation

Before modifying code, the agent must identify:

* the requested observable behavior and the affected contracts — the CLI
  surface, the `rdv/1` wire protocol (spec + fixtures) and the no-log invariant;
* failure cases, boundaries, security implications (untrusted network input,
  token handling, path/traversal on the ready file), concurrency and state
  transitions (TTL prune, refresh, graceful shutdown);
* the existing implementation and tests (white-box in `python/tests/`,
  language-neutral in `tests/`);
* reusable models/utilities (pydantic models in `protocol.py`; the shared frame
  builders and fixtures) and whether the `hsync-common` SSOT already provides
  the needed contract;
* the cross-language and packaging impact (see the table below).

Do not invent unsupported requirements. Apply these checks proportionally to
trivial documentation-only or formatting-only changes.

| Implementation | Observable behavior | Cross-language / artifact impact |
| --- | --- | --- |
| `python/` | CLI, `rdv/1` wire behavior, no-log | spec, fixtures, `c/`, root `tests/`, `bench/`, `compile.sh`, `packaging/`, docs |
| `c/` | same CLI + `rdv/1` wire behavior | spec, fixtures, `python/`, root `tests/`, `bench/`, `compile.sh`, `packaging/`, docs |
| root (`tests/`, `bench/`, `fixtures/`, spec) | the shared contract itself | every implementation |

### 2. First Implementation Pass

Implement the smallest complete change satisfying the acceptance criteria. Do not add speculative functionality, hide failures with broad catches or silent fallbacks, weaken tests, or change unrelated code. In C, "silent fallback" includes ignoring a return code or an unchecked `malloc`/`read` result on the hot path.

### 3. Mandatory Verification Pass

After the first implementation pass, and before finalizing:

1. Re-read the original request and acceptance criteria without assuming the implementation is correct.
2. Inspect the **complete diff** (`cd hsync-rendezvous && git diff` / `git status`), including tests, fixtures, the spec, `compile.sh`, `packaging/`, the man page, `llm-wiki/` and `docs/`. Reviewing your own edit history is not enough — read the actual diff.
3. Trace normal, invalid-input, empty/missing, minimum/maximum, oversized, malformed, pipelined-frames, TTL-expiry, cancellation, graceful-shutdown, partial-write and rate-limit paths where applicable.
4. Verify consistency across the spec, the committed fixtures, the frame models of **every** implementation, the CLI/env contract (flags ↔ `HSYNC_RENDEZVOUS_*` ↔ man page ↔ service units), the packaging scripts and the documentation.
5. Run the narrowest relevant checks first (see below), then the broader ones when practical.
6. Correct every issue found and rerun the affected checks.

Documentation reference integrity (Documentation Maintenance §7) is part of step 4: every `path::symbol`, backticked path, link/anchor and quoted derived value in `llm-wiki/` must resolve or be corrected in the same task.

Diff inspection and executed checks are required; stating that the implementation was reviewed is insufficient.

#### Commands — Python (v1, in-project virtualenv)

Dependencies are installed with `poetry install`, which creates the in-project
`.venv` (the virtualenv is local and is **not** committed). `ruff` is **not** on
`PATH`: always invoke the tools through that virtualenv, prefixing every command
with `cd hsync-rendezvous/python &&`, one command per shell invocation.

```
# create/refresh the in-project virtualenv from pyproject.toml + poetry.lock
cd hsync-rendezvous/python && poetry install
# targeted unit test, then the full unit suite
cd hsync-rendezvous/python && .venv/bin/python -m pytest -q tests/test_handler.py::test_name
cd hsync-rendezvous/python && .venv/bin/python -m pytest -q
# lint + format check + types
cd hsync-rendezvous/python && .venv/bin/python -m ruff check .
cd hsync-rendezvous/python && .venv/bin/python -m ruff format --check .
cd hsync-rendezvous/python && .venv/bin/python -m mypy src/hsync_rendezvous
```

#### Commands — language-neutral code at the repository root (`tests/`, `bench/`)

These are linted with the root `ruff.toml` but run with the Python virtualenv's
interpreter (it is the test runner only):

```
cd hsync-rendezvous && python/.venv/bin/python -m ruff check tests bench
cd hsync-rendezvous && HSYNC_BB_RENDEZVOUS=1 python/.venv/bin/python -m pytest -q tests/
cd hsync-rendezvous && HSYNC_BB_RENDEZVOUS=1 HSYNC_RENDEZVOUS_BIN=/path/to/c/binary \
    python/.venv/bin/python -m pytest -q tests/
```

#### Commands — C (`c/`, once the sources exist)

```
cd hsync-rendezvous/c && clang-format --dry-run --Werror src/*.c include/*.h
cd hsync-rendezvous/c && clang-tidy src/*.c -- -std=c11 -Iinclude
cd hsync-rendezvous/c && make test          # -fsanitize=address,undefined build
```

Plus, when the change touches memory management or buffer arithmetic, the
ASan/UBSan run (and `valgrind` where ASan is unavailable); when it touches the
untrusted-input frame decoder, the libFuzzer targets (see the C section).

Notes:
* Read what a command **actually printed**: never report a check as passed when
  it did not run, and never treat `command not found` (exit 127) as a passing
  result. `ruff check` exits non-zero when violations remain — that is a real
  finding to fix, never to mask with `|| true`.
* The workspace-root `Makefile` fans out here too: `make lint` covers `python/`
  **and** the language-neutral `tests/` + `bench/`, `make test-python` runs
  `python/tests`, and `make test-bb-rendezvous` runs the black-box suite
  (`HSYNC_BB_RENDEZVOUS=1`). The commands above remain the single-project form.
* Never run `ruff check`/`ruff format` from the workspace root, and never chain
  several of these commands with `;` on one line.

### 4. Regression and Contract Tests

Every bug fix must include a regression test that fails against the faulty
behavior and passes after the fix. New behavior must cover its success path and
the relevant failure/boundary cases.

* **Protocol changes**: update `protocol-spec/rdv-1.md`, `fixtures/` and every
  implementation atomically, and keep a **drift test** that validates each
  implementation's frame models against the committed fixtures. The same fixtures
  must be consumed by the C suite: mirror the Python drift test, never
  re-derive the expected bytes locally.
* **CLI / env / packaging changes**: extend the language-neutral suite in
  `tests/` (exit codes, `--version`, fail-fast refusals) and update the man page,
  service units and `docs/usage.md`.
* A test may be omitted only when genuinely impractical, with the reason and the
  alternative verification reported.

**Black-box tests (`test_bb_*`)** must verify the public contract, never the implementation. Every new `test_bb_*` test must be able to answer **YES** to all of these questions:

* Does the test use only public CLI commands, documented environment variables,
  or `rdv/1` wire frames?
* If the internal implementation were completely rewritten — including in another
  language — while keeping the same contract, would the test still pass?
* Does the test verify a behavior that the end user or a remote client can
  actually observe?

Black-box tests must go through the shared harness in `tests/harness.py` (frame
builders, binary resolution via `HSYNC_RENDEZVOUS_BIN`, environment scrubbing) —
never a hand-rolled process spawn with an unscrubbed environment. Readiness is
awaited through the `HSYNC_RENDEZVOUS_READY_FILE` PID file, never with sleeps.
Randomized inputs must log their seed (`[seed] <n>`) so failures are
reproducible.

### 4-bis. Test Environment Isolation

* **Clean start**: every test or fixture must verify that the starting
  environment is clean (no leftover temp files, no stray `HSYNC_*` environment
  variables, no orphaned processes, no global state polluted by a previous
  test). The ready-file path must be a fresh, unique location.
* **Clean exit**: every test must restore the initial state when it finishes,
  even on error or interruption (`try`/`finally`, fixtures, `tmp_path`). Started
  node processes must be terminated (and reaped) on every exit path.
* **No cross-test contamination**: a test's outcome must never depend on
  execution order or on whether a previous test failed. C tests must not share
  global mutable state; the routing table must be owned per test instance.

### 5. Bounded Correction Cycle

Fix issues found during verification and repeat the relevant checks, for at most two review-and-correction cycles unless the user requests more. Do not finalize with known failures. If blocked by dependencies, credentials, external services, platform tooling (missing C compiler, sanitizer runtime, libFuzzer or `valgrind`), UAC/network availability or pre-existing failures, report the blocker precisely and stop changing code. Never claim a check passed unless it completed successfully.

### 6. Definition of Done

Completion requires satisfied acceptance criteria, complete diff review, passing relevant checks, adequate tests, synchronized spec/fixtures/implementations/packaging/documentation, and no known correctness or security defect. The final response must state what changed, the commands executed and their outcomes, the checks not executed and why, and the remaining risks or limitations.

For authentication, secrets (group keys), network trust, protocol contracts,
destructive or privacy-relevant paths (the no-log invariant), persistence and
concurrency changes, request an independent review when available; this does not
replace self-verification or tests.

---

## 🐍 Python Standards & Code Reuse (`python/**/*.py`, `tests/`, `bench/`)

### 1. Strict DRY & Duplication Prevention
* **Pre-implementation Check**: Before writing any new function, component, or logic, you **MUST** search the relevant module and shared utility/model locations (`python/src/hsync_rendezvous/`, `tests/harness.py`, `fixtures/`) for an existing implementation. Expand to a repository-wide search only when the wiki and local search are insufficient.
* **No Copy-Paste-Modify**: Copying, pasting, and slightly modifying existing code snippets for a new use case is **STRICTLY PROHIBITED** — including duplicating a frame builder that already lives in `tests/harness.py`.
* **Refactoring over Duplication**: If *similar* (but not identical) logic already exists, **DO NOT** create a duplicate. Instead, refactor the existing code to make it more generic, parameterized, and reusable. Briefly explain your refactoring logic when doing so.
* **Rule of Three**: If you identify or need the same logic/code block for a second time, treat it as a warning. If requested for a third time, you **MUST** extract it into a standalone utility function, helper, or common base class.
* **No Inline Helpers**: Writing nested or inline helper functions inside main functions is **PROHIBITED** if the logic is generic and extractable. Always promote exportation and centralized reuse.
* **Semantic Reuse over Superficial Similarity**: Extract shared logic only when behavior, invariants, and reasons to change are the same. Prefer small local duplication over an incorrect or unstable abstraction.

### 2. Typing & Data Models
* **Centralized Models**: Strictly use type hints. For data structures, **ALWAYS** reuse the existing pydantic frame models in `python/src/hsync_rendezvous/protocol.py` (or the `hsync-common` models when the contract lives there).
* **No Manual Parsing**: **DO NOT** perform manual parsing or complex dictionary navigation (e.g., `dict.get()`) if a pydantic class already exists to validate and instantiate that specific frame.
* **SSOT discipline**: shared contracts come from `hsync-common`, not from a local re-definition. The CID pattern and the bucket-name rule are imported from `hsync-common`; any future local mirror is temporary and must be replaced by the `hsync-common` import with a drift test as soon as the dependency exposes it.

### 3. Modularity & Maintainability
* **File Responsibility Control**: Split a file when it contains multiple independently changing responsibilities (as `server.py`/`handler.py`/`routing.py` already do), not merely because of line count. Do not perform unrelated structural refactoring as part of a narrowly scoped fix.

---

## 🔧 C Standards & Code Reuse (`c/**/*.c`, `c/**/*.h`)

The C implementation is a second implementation of the **same** contract: it
never gets its own dialect, its own spec or its own fixtures.

### 1. Safety and C idioms
* **Zero warnings**: every translation unit compiles under
  `-std=c11 -Wall -Wextra -Wpedantic -Werror` (`clang` or `gcc`); a warning is a
  defect, not a note.
* **No undefined behaviour**: bounds are checked before every index/pointer
  access, signed overflow is avoided (an unsigned type or an explicit range check),
  strict aliasing is respected and no object is read after `free`. The whole
  suite runs under `-fsanitize=address,undefined` (plus `-fsanitize=thread` for
  the threading paths) and finishes clean; `valgrind` is the fallback where ASan
  is unavailable.
* **Checked allocations, single ownership**: every `malloc`/`realloc` result is
  checked, every allocation has exactly one owner and one matching `free`, and
  cleanup follows a single `goto cleanup` path so an early error return cannot
  leak. No `strcpy`/`strcat`/`sprintf`/`gets`: use `snprintf`, `memcpy` with an
  explicit size, and the `strn*` variants.
* **No process termination as error handling**: a production path returns an
  error code and the caller decides; `abort()`/`assert()` are reserved for
  programmer errors in debug builds, never for input validation.
* **No silent fallback**: do not ignore a return code, do not cast away `const`,
  do not add lenient re-interpretation, aliases or compatibility fallbacks to the
  frame decoding.
* **Fuzzing the untrusted input**: any component that processes raw network data
  or untrusted input — in this repository the `rdv/1` NDJSON frame decoder and
  its length/UTF-8/field validation — **must** ship libFuzzer targets
  (`clang -fsanitize=fuzzer,address`), seeded from the committed `fixtures/`.
* **Concurrency and state**: the routing table is in-memory state shared across
  sockets; protect it with a documented lock order, never hold a lock across a
  blocking call or a plugin callback, and never persist state to disk (the no-log
  invariant applies to C exactly as it does to Python).
* **Behavioural parity**: refusals (`token_required`, `rate_limited` +
  `retry_after`, and `overloaded` + advisory `retry_after` for capacity
  backpressure), framing, STUN-echo semantics and TTL handling must be
  indistinguishable from the Python implementation on the wire — that is exactly
  what the language-neutral `tests/` suite verifies.

### 2. Types and models
* **Typed frames**: represent every `rdv/1` frame with a `struct` per frame, one
  shared `enum` for the frame kind, and the project's JSON library — never
  hand-rolled string concatenation or manual byte slicing where a typed model
  applies. An unknown or targeted field rejects the frame (rigid schema), never a
  best-effort partial parse.
* **Fixed-width types**: protocol integers are `uint32_t`/`int64_t`/…, sizes are
  `size_t`, and every narrowing conversion is explicit and range-checked.

### 3. DRY, headers and modularity
* **No Copy-Paste-Modify**: copying a module and slightly adapting it for another
  purpose is **STRICTLY PROHIBITED**.
* **Rule of Three**: when the same logic is needed a second time, treat it as a
  warning; at the third occurrence you **MUST** extract it into a standalone
  function or a shared module with a single declaration in a header.
* **No inline helpers**: nested functions and GNU statement expressions are
  **PROHIBITED**; promote extractable logic to a `static` helper in the same
  translation unit or to a documented module-level function.
* **Semantic reuse over superficial similarity**: extract shared logic only when
  behaviour, invariants and reasons to change are the same; prefer small local
  duplication over an incorrect abstraction.
* **Modularity**: split a file when it carries multiple independently changing
  responsibilities, not merely because of line count; every non-`static` symbol
  has exactly one declaration in a header.

### 4. Build and layout
* The sources live under `hsync-rendezvous/c/` and must not fork
  `protocol-spec/rdv-1.md` or `fixtures/`.
* The C CLI exposes the same commands, flags, environment variables, exit codes
  and `--version` shape as the Python implementation, so the language-neutral
  suite passes unchanged against `HSYNC_RENDEZVOUS_BIN=<c binary>`.
* Do not add a dependency, change the language standard or bump pinned versions
  unless the task explicitly requires it: this is a no-log daemon, keep the
  dependency surface minimal (C11 plus the QUIC/JSON libraries the port chooses).

---

## ✂️ Comment Policy

* **Verify usefulness before writing**: whenever you add or edit a code comment,
  first check that it conveys information a reader **cannot deduce from the code
  itself** — rationale, invariants, protocol/format constraints, external
  references, non-obvious gotchas. Delete comments that merely restate what the
  code plainly does, paraphrase the next line, or duplicate a name.
* **Simplify without losing meaning**: prefer the shortest wording that preserves
  the non-derivable information; never drop a real constraint just to shorten the
  comment. A comment is justified only when its removal would lose meaning.
* **Keep the code compact**: comments must not add narration, redundant history
  or speculation; keep them focused and the surrounding code lean.

---

## 💬 Language Policy

* **English-only**: commit messages (subject and body), the internal agent wiki
  (`llm-wiki/`), and the user documentation (`docs/`) MUST be written in
  English, regardless of the language used in the task.
* This also applies to code comments, doc comments (Python docstrings and C
  `/** */` doc comments), error messages and CLI help strings.
* Commit messages follow Conventional Commits: `type(scope): description`
  (feat, fix, docs, style, refactor, test, chore, perf, ci, build). Keep the
  message concise: precise, but no elaboration.

---

## 📝 Changelog Maintenance

Before completing any task that introduces a user-facing change, bug fix, or
notable internal improvement, evaluate whether the change warrants an entry in
`CHANGELOG.md` following the [Keep a Changelog](https://keepachangelog.com/)
format. Add an entry under an `## [Unreleased]` section when relevant. The
repository does not ship a `CHANGELOG.md` yet: the first change that warrants an
entry creates it.

* **Concise entries**: one short, precise line per change, without
  elaboration.

* **Explicit User Confirmation Required**: Do not edit `CHANGELOG.md` unless the
  user has explicitly confirmed the update for the current task. If an entry
  appears warranted and the user has not already requested it, pause before
  editing the file and ask whether they want the changelog updated. Proceed only
  after an affirmative response; otherwise leave `CHANGELOG.md` unchanged.

Irrelevant for: typo fixes, purely internal refactors with no behavioral change,
CI/formatting-only changes, or doc updates that don't document new features.
