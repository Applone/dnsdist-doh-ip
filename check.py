import sys

# Check if GIL is currently active
def is_gil_active():
    if hasattr(sys, '_is_gil_enabled'):
        return sys._is_gil_enabled()
    return True

print(f"Is GIL enabled? {is_gil_active()}")
