"""Entry point: ``--version`` is answered before the CLI stack is imported.

The probe is used by packaging scripts and health checks; importing Typer,
pydantic, cryptography and aioquic to print a static string costs ~250 ms. The
loaded-module probe pins that the fast path really skips them, and the module
invocation pins the exact stdout the CLI has always produced.
"""

from __future__ import annotations

import subprocess
import sys

from hsync_rendezvous import __version__

_EXPECTED = f"hsync-rendezvous {__version__} (rdv/1, Python v1)\n"


def _run_main(argv: list[str]) -> subprocess.CompletedProcess[str]:
    """Run ``main()`` with *argv* and report which heavy modules it imported."""
    code = (
        "import sys\n"
        f"sys.argv = {argv!r}\n"
        "from hsync_rendezvous.main import main\n"
        "main()\n"
        "loaded = [m for m in ('typer', 'hsync_rendezvous.cli') if m in sys.modules]\n"
        "print(','.join(loaded), file=sys.stderr)\n"
    )
    return subprocess.run([sys.executable, "-c", code], capture_output=True, text=True, check=False)


def test_version_fast_path_skips_the_cli_stack() -> None:
    proc = _run_main(["hsync-rendezvous", "--version"])

    assert proc.returncode == 0, proc.stderr
    assert proc.stdout == _EXPECTED
    assert proc.stderr.strip() == "", f"fast path imported heavy modules: {proc.stderr}"


def test_module_invocation_prints_the_same_version_line() -> None:
    proc = subprocess.run(
        [sys.executable, "-m", "hsync_rendezvous", "--version"],
        capture_output=True,
        text=True,
        check=False,
    )

    assert proc.returncode == 0, proc.stderr
    assert proc.stdout == _EXPECTED
