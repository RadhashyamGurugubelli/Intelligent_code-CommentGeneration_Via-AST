"""Test configuration to guarantee that the project root is on the Python import path.

When pytest is invoked from the virtual‑environment scripts directory, the
project root may not be automatically added to ``sys.path``. This leads to
import errors such as ``ModuleNotFoundError: No module named 'backend'`` in the
test suite. By inserting the absolute path of the repository root at the
start of ``sys.path`` we make the ``backend`` package (and any other local
modules) importable without affecting the runtime behavior of the application.
"""

import os
import sys

PROJECT_ROOT = os.path.abspath(os.path.dirname(__file__))
if PROJECT_ROOT not in sys.path:
    sys.path.insert(0, PROJECT_ROOT)
