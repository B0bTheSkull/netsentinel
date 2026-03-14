"""Port scan detection monitor using SYN packet tracking."""
import time
from collections import defaultdict
from scapy.layers.inet import IP, TCP


class PortScanMonitor:
    def __init__(self, alerter, threshold=15, window=10, whitelist=None):
        self.alerter = alerter
        self.threshold = threshold
        self.window = window
        self.whitelist = set(whitelist or [])
        # ip -> {dst_port -> first_seen_timestamp}
        self.syn_tracker = defaultdict(dict)
        self.alerted = set()  # avoid repeat alerts

    def process(self, pkt):
        if not (pkt.haslayer(IP) and pkt.haslayer(TCP)):
            return
        tcp = pkt[TCP]
        ip = pkt[IP]

        # Only SYN packets (SYN=1, ACK=0)
        if not (tcp.flags & 0x02 and not tcp.flags & 0x10):
            return

        src = ip.src
        dst_port = tcp.dport

        if src in self.whitelist:
            return

        now = time.time()
        # Clean up old entries outside the window
        self.syn_tracker[src] = {
            p: t for p, t in self.syn_tracker[src].items() if now - t < self.window
        }
        self.syn_tracker[src][dst_port] = now

        port_count = len(self.syn_tracker[src])

        if port_count >= self.threshold and src not in self.alerted:
            self.alerted.add(src)
            ports = sorted(self.syn_tracker[src].keys())
            self.alerter.alert(
                severity="HIGH",
                event_type="port_scan",
                source_ip=src,
                destination=ip.dst,
                detail=f"Port scan detected: {port_count} ports in {self.window}s",
                extra={"ports_scanned": ports[:20], "port_count": port_count}
            )
