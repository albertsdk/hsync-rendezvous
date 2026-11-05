# C implementation of `hsync-rendezvous` (future — v2)

**Not started.** This directory will hold the C11 implementation of the same
`rdv/1` wire protocol (see [`../protocol-spec/rdv-1.md`](../protocol-spec/rdv-1.md)),
targeted at the full "thousands of handshakes/s" requirement.

The C port is an **additive v2**, not a prerequisite: the Python
implementation under `../python/` is the reference and is **complete and stable
(v1)**, so `hsync-rendezvous` is fully functional today. Do not fork the spec here.

Target toolchain: **C11** (`clang` or `gcc`) with `make`. The crate layout is
this directory with its own `compile.sh` and `Makefile` once the port lands; the
QUIC/TCP transport stack is chosen together with the port and recorded in
[`../llm-wiki/decisions.md`](../llm-wiki/decisions.md).
