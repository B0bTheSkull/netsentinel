import os
import sys

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))


class FakeAlerter:
    """Records alert() calls instead of printing/logging."""
    def __init__(self):
        self.alerts = []

    def alert(self, **kwargs):
        self.alerts.append(kwargs)
        return kwargs
