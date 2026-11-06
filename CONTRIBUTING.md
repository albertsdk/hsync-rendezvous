# Contributing to hsync-rendezvous

Thanks for your interest in contributing! This guide covers the development
workflow for the HSYNC rendezvous — the optional, stateless `rdv/1` rendezvous node
for P2P topologies.

`hsync-rendezvous` is a **multi-language** repository: one wire protocol with
several implementations of the *same* contract. `python/` is the reference (v1);
`c/` is the planned v2. The specification and the fixtures are shared, so a
wire change must keep every implementation byte-identical.

## Prerequisites

### Python implementation (`python/`, v1)

- Python `>=3.12,<3.15` (lint/type target: **3.13**)
- [Poetry](https://python-poetry.org/) to create the in-project virtualenv
  (`.venv/` is local and **not** committed)

### C implementation (`c/`, planned v2)

- A C11 compiler (`clang` or `gcc`) with `make` — the sources do not exist yet
- `clang-format` / `clang-tidy` for the style checks, `clang` (or `gcc`) with
  `-fsanitize=address,undefined` for the test build

### Packaging and black-box tests

- `dpkg-deb` (dpkg-dev); Docker + `qemu-user-static` for `rpi` / `deb-all`
- `fakeroot` (optional) for `.deb` assembly

## Repository Layout

| Path | Content |
|---|---|
| `protocol-spec/rdv-1.md` | Wire-protocol specification — the **single source of truth (SSOT)** |
| `fixtures/rendezvous-*.json` | Shared protocol fixtures (single source for every language) |
| `tests/` | **Language-neutral** black-box suite (spawns the binary, wire-only) |
| `bench/` | Benchmarks; L2/L3 are language-neutral, L1/L4/L5 are Python-internal |
| `python/` | v1 implementation — Python + aioquic, with its white-box unit suite |
| `c/` | v2 implementation — C11 (planned, not started) |
| `packaging/` | OS service units (systemd / launchd / WinSW) and the `.deb` payload |
| `compile.sh` | Root build entry point (`native`/`rpi`/`deb`/`deb-all`, `-l/--language`) |
| `llm-wiki/` | Internal agent knowledge base |
| `docs/` | End-user documentation |
| `AGENTS.md` | Coding rules for AI agents — a useful checklist for humans too |

Each implementation is built, linted and tested from **its own** directory; the
root scripts only dispatch and assemble packages.

## Setup

```bash
# Python (v1): creates the in-project .venv from pyproject.toml + poetry.lock
cd hsync-rendezvous/python && poetry install
```

## Building

```bash
# Python standalone binary (PyInstaller, per-language script)
cd hsync-rendezvous/python && ./compile.sh                  # host OS/arch
cd hsync-rendezvous/python && ./compile.sh -t onedir -o build/onedir

# User-facing artifacts (root entry point; python is the only language today)
cd hsync-rendezvous && ./compile.sh -t native               # host standalone
cd hsync-rendezvous && ./compile.sh -t rpi                  # Raspberry Pi armhf+arm64 (Docker)
cd hsync-rendezvous && ./compile.sh -t deb                  # host architecture .deb
cd hsync-rendezvous && ./compile.sh -t deb-all              # amd64, arm64, armhf (Docker)
cd hsync-rendezvous && ./compile.sh -l python -t deb
```

`-l/--language` defaults to `python` and rejects `c` until that port exists;
`-v/--version` overrides the version read from `python/pyproject.toml`.

## Code Style

### Python

[ruff](https://docs.astral.sh/ruff/) for linting and formatting (line length 100,
target `py313`), plus mypy:

```bash
cd hsync-rendezvous/python && .venv/bin/python -m ruff check .
cd hsync-rendezvous/python && .venv/bin/python -m ruff format --check .
cd hsync-rendezvous/python && .venv/bin/python -m mypy src/hsync_rendezvous
```

`ruff` is **not** on `PATH`: always invoke it through the virtualenv as
`.venv/bin/python -m ruff`. `ruff check` exits non-zero when violations remain —
fix them, never mask them with `|| true`.

The language-neutral code at the repository root (`tests/`, `bench/`) is linted
with the root `ruff.toml`:

```bash
cd hsync-rendezvous && python/.venv/bin/python -m ruff check tests bench
```

### C (once `c/` lands)

```bash
cd hsync-rendezvous/c && clang-format --dry-run --Werror src/*.c include/*.h
cd hsync-rendezvous/c && clang-tidy src/*.c -- -std=c11 -Iinclude
cd hsync-rendezvous/c && make test        # sanitizer build: -fsanitize=address,undefined
```

Every build is `-std=c11 -Wall -Wextra -Wpedantic -Werror` and must compile
without warnings. Undefined behaviour is a defect, not an acceptable outcome:
bounds are checked before every array/index access, allocations are checked,
`strcpy`/`sprintf`/`gets` are prohibited in favour of the size-bounded variants,
and each allocation has a single, explicit owner. A component that decodes
untrusted bytes must ship a libFuzzer target (`clang -fsanitize=fuzzer`) and a
memory-safety run of the suite under ASan/UBSan (valgrind where ASan is not
available).

## Tests

### Python unit suite (white-box)

```bash
# full suite, or a single test
cd hsync-rendezvous/python && .venv/bin/python -m pytest -q
cd hsync-rendezvous/python && .venv/bin/python -m pytest -q tests/test_handler.py::test_name
```

### Black-box suite (language-neutral)

Gated by `HSYNC_BB_RENDEZVOUS=1`; the Python virtualenv acts only as the *test
runner* (pytest + aioquic for the wire client). The tests spawn the executable and
observe only the public surface — the CLI and the `rdv/1` wire — so they must
pass unchanged against another implementation.

```bash
cd hsync-rendezvous && HSYNC_BB_RENDEZVOUS=1 python/.venv/bin/python -m pytest -q tests/

# run the same suite against the future C binary
cd hsync-rendezvous && HSYNC_BB_RENDEZVOUS=1 HSYNC_RENDEZVOUS_BIN=/path/to/binary \
    python/.venv/bin/python -m pytest -q tests/
```

The opt-in stress suite adds `HSYNC_BB_STRESS=1` on top, with scale knobs read at
import time (`HSYNC_BB_RENDEZVOUS_STRESS_CONNECTIONS`, `…_ROUNDS`, `…_PEERS`,
`…_MAX_P99_MS`).

### Benchmarks

```bash
# L1 — handler micro-benchmark (Python-internal)
cd hsync-rendezvous && python/.venv/bin/python bench/bench_handler.py --count 2000

# L2 — QUIC loopback load (language-neutral)
cd hsync-rendezvous && python/.venv/bin/python bench/bench_quic.py --connections 50 --frames 200
```

L2/L3 drive the binary through the wire protocol only (path via
`HSYNC_RENDEZVOUS_BIN`, default the Python build), so they run unchanged against the
C port. The L2 load harness (`bench_quic.py`) drives QUIC/UDP; the functional and
black-box coverage spans both transports (QUIC/UDP and TLS/TCP). See
[`bench/README.md`](bench/README.md) for the full tier table and
the measurement methodology.

> From the workspace root, `make lint` (both ruff surfaces), `make test-python`
> (unit tests) and `make test-bb-rendezvous` (black-box suite) run the same checks;
> the commands above are the single-repository form.

## Contract Discipline

`protocol-spec/rdv-1.md` is the single source of truth: never fork it inside an
implementation, and never let one implementation drift from it.

- Every frame model rejects unknown fields (pydantic `extra="forbid"` in Python).
  A malformed or targeted frame is silently dropped, never reinterpreted.
- A protocol change updates the spec, the committed `fixtures/`, the frame models
  of **every** implementation and the language-neutral suite in the same change.
- These hard invariants must survive every change:
  - **No-log** — no peer data (IPs, CIDs, timestamps) is ever written to disk,
    enforced by `python/tests/test_nolog.py` under a read-only filesystem.
  - **RAM only** — the routing table, keys and rate-limit windows have no
    persistence layer.
  - **Rigid schema** and **protected buckets** — constant-time token compare and
    uniform refusals that reveal nothing about bucket existence.
  - **Zero backward compatibility** — a breaking contract change is a protocol
    version bump, with no shim and no migration phase.

## Cross-Project Impact

The `rdv/1` contract is mirrored outside this repository, so a wire change must
update the consumers and their parity tests atomically:

- `hsync-common` — `hsync_common/protocol/rendezvous.py` (frames + validators) and
  the committed fixtures
- `hsync-client` — `RendezvousClient` / the rdv rendezvous plan
- `hsync-android` — the Kotlin `RendezvousProtocol` mirror

## Documentation

Two sets, both updated within the same change:

- `llm-wiki/` — internal agent knowledge base (architecture, data models, decisions)
- `docs/` — end-user documentation (welcome page, usage reference)

Any user-visible change — CLI flags, `HSYNC_RENDEZVOUS_*` variables, defaults or
behavior — must also keep these in sync:

- `packaging/deb/usr/share/man/man1/hsync-rendezvous.1` (man page: `OPTIONS`,
  `ENVIRONMENT`, `EXIT STATUS`, examples)
- the OS service units in `packaging/` and the `--help` text of
  `python/compile.sh` / `compile.sh`
- `README.md` (layout table, quick start, documentation index)

## Commit Messages

Follow [Conventional Commits](https://www.conventionalcommits.org/):
`type(scope): summary` (`feat`, `fix`, `docs`, `refactor`, `test`, `chore`, …).

## Pull Requests

- `hsync-rendezvous` is its own git repository: verify it with
  `git rev-parse --git-dir` before any git command, and make **one commit per
  repository**.
- Inspect what you are about to commit (`git status --short`,
  `git diff --cached`) and prefer explicit paths over `git add -A`.
- **Never stage build outputs or secrets**: `dist/`, `build/`, `target/`,
  `*.deb`, `*.o`/`*.a`/`*.so`, `*.env`, and any local `group-keys` file.
- Keep changes focused, covered by a test that fails before the fix, and free of
  speculative behavior, silent fallbacks or weakened assertions.
- Before opening a PR, run the Python unit suite, the lint/format/mypy checks and
  the black-box suite (`HSYNC_BB_RENDEZVOUS=1`); when the change touches the wire
  contract, add the cross-project updates listed above.