"""Process entry point: answer ``--version`` before importing the CLI stack.

The console script, ``python -m hsync_rendezvous`` and the frozen builds
(``python/compile.sh`` uses ``__main__.py`` as the PyInstaller entry) all route
through here. ``--version`` prints a static string, so it must not import Typer,
pydantic, cryptography or aioquic: the probe is used by packaging scripts and
health checks and would otherwise pay the whole daemon import chain. Every other
invocation falls through to the Typer app unchanged.
"""

from __future__ import annotations

import sys


def main() -> None:
    """Answer the version probe, else dispatch to the CLI."""
    # Only a leading flag is intercepted: ``run --version`` and every other
    # argument combination keep their Typer semantics (no token after the flag is
    # inspected), so this can only replace a path Typer resolves identically.
    if sys.argv[1:2] == ["--version"]:
        from hsync_rendezvous import __version__

        print(f"hsync-rendezvous {__version__} (rdv/1, Python v1)")
        return

    from hsync_rendezvous.cli import app

    app()
