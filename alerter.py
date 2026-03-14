"""Colored console alerting and JSON logging for NetSentinel."""
import json
import sys
from datetime import datetime
from pathlib import Path

RESET = "\033[0m"
BOLD = "\033[1m"
RED = "\033[91m"
ORANGE = "\033[31m"
YELLOW = "\033[33m"
CYAN = "\033[36m"
GREEN = "\033[32m"
WHITE = "\033[37m"

SEVERITY_COLORS = {
    "CRITICAL": RED,
    "HIGH": ORANGE,
    "MEDIUM": YELLOW,
    "LOW": CYAN,
    "INFO": WHITE,
}


class Alerter:
    def __init__(self, config):
        self.config = config
        self.log_file = config.get("log_file", "netsentinel.json")
        self.console = config.get("alerts", {}).get("console", True)
        self.do_log = config.get("alerts", {}).get("log_file", True)

    def _color(self, text, color):
        return f"{color}{text}{RESET}"

    def banner(self):
        print(f"""
{self._color('╔══════════════════════════════════════════╗', CYAN)}
{self._color('║         NetSentinel v1.0                 ║', CYAN)}
{self._color('║   Real-Time Network Threat Monitor       ║', CYAN)}
{self._color('╚══════════════════════════════════════════╝', CYAN)}
""")

    def alert(self, severity, event_type, source_ip, destination, detail, extra=None):
        event = {
            "timestamp": datetime.now().isoformat(),
            "severity": severity,
            "event_type": event_type,
            "source_ip": source_ip,
            "destination": destination,
            "detail": detail,
        }
        if extra:
            event.update(extra)

        if self.console:
            color = SEVERITY_COLORS.get(severity, WHITE)
            ts = datetime.now().strftime("%H:%M:%S")
            print(
                f"{self._color(ts, WHITE)} "
                f"{self._color(f'[{severity}]', color)} "
                f"{self._color(event_type.replace('_',' ').upper(), BOLD)} "
                f"| {self._color(source_ip, YELLOW)} → {destination} "
                f"| {detail}"
            )

        if self.do_log:
            with open(self.log_file, "a") as f:
                f.write(json.dumps(event) + "\n")

        return event

    def info(self, msg):
        if self.console:
            ts = datetime.now().strftime("%H:%M:%S")
            print(f"{self._color(ts, WHITE)} {self._color('[*]', CYAN)} {msg}")
