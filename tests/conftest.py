"""Make the project root importable so tests can `import bind9_setup`."""
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
