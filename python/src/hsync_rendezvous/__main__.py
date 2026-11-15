"""Allow ``python -m hsync_rendezvous`` and the frozen builds.

The entry lives in :mod:`hsync_rendezvous.main` so ``--version`` avoids the CLI
import chain (see that module); ``python/compile.sh`` uses this file as the
PyInstaller entry point, so the frozen binary shares the same fast path.
"""

from hsync_rendezvous.main import main

if __name__ == "__main__":
    main()
