"""ICMP flood detection monitor."""
import time
from collections import defaultdict
from scapy.layers.inet import IP, ICMP


class ICMPMonitor:
    def __init__(self, alerter, threshold=50, window=5, whitelist=None):
        self.alerter = alerter
        self.threshold = threshold
        self.window = window
        self.whitelist = set(whitelist or [])
        self.icmp_tracker = defaultdict(list)  # ip -> [timestamps]
        self.alerted = set()

    def process(self, pkt):
        if not (pkt.haslayer(IP) and pkt.haslayer(ICMP)):
            return
        icmp = pkt[ICMP]
        if icmp.type != 8:  # Echo request only
            return

        src = pkt[IP].src
        if src in self.whitelist:
            return

        now = time.time()
        self.icmp_tracker[src] = [t for t in self.icmp_tracker[src] if now - t < self.window]
        self.icmp_tracker[src].append(now)

        count = len(self.icmp_tracker[src])
        if count >= self.threshold and src not in self.alerted:
            self.alerted.add(src)
            self.alerter.alert(
                severity="HIGH",
                event_type="icmp_flood",
                source_ip=src,
                destination=pkt[IP].dst,
                detail=f"ICMP flood: {count} echo requests in {self.window}s from {src}",
                extra={"packet_count": count, "window_seconds": self.window}
            )
