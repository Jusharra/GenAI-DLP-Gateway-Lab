import os
import sys

# Add the python/ directory (one level up from tests/) to sys.path
THIS_DIR = os.path.dirname(__file__)
PY_ROOT = os.path.abspath(os.path.join(THIS_DIR, ".."))

if PY_ROOT not in sys.path:
    sys.path.insert(0, PY_ROOT)
