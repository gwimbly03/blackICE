# core/target.py
class _Atk:
    def __init__(self):
        self._target = None

    def set_target(self, value: str) -> None:
        """Set the global target (IP or domain)."""
        self._target = value

    def get_target(self) -> str:
        """Return the globally stored target or None if not set."""
        return self._target

# Export a single global instance named `atk` so code can do:
# from core.target import atk
# atk.set_target("1.2.3.4")
atk = _Atk()

