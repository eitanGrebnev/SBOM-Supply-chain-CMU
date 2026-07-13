"""Dev-mode convenience shim — run the CLI without installing the package.

For everyday use, install the package (`pip install -e .`) and run the
`sbom-scorer` command instead — see README.md "Setup". This file just lets
you run `python main.py ...` straight out of a fresh clone with no install
step, which is handy while iterating on the stubs in sbom_scorer/.
"""

import sys

from sbom_scorer.cli import main

if __name__ == "__main__":
    sys.exit(main())
