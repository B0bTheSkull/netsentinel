"""DNS anomaly detection: hijacking and tunneling."""
import logging
import math
from collections import defaultdict
from scapy.layers.dns import DNS, DNSRR
from scapy.layers.inet import IP

logger = logging.getLogger("netsentinel.dns")


def shannon_entropy(s):
    """Calculate Shannon entropy of a string."""
    if not s:
        return 0
    freq = defaultdict(int)
    for c in s:
        freq[c] += 1
    length = len(s)
    return -sum((count / length) * math.log2(count / length) for count in freq.values())


class DNSMonitor:
    def __init__(self, alerter, entropy_threshold=3.5, track_changes=True):
        self.alerter = alerter
        self.entropy_threshold = entropy_threshold
        self.track_changes = track_changes
        self.dns_cache = {}  # domain -> set of IPs seen

    def process(self, pkt):
        if not pkt.haslayer(DNS):
            return
        dns = pkt[DNS]

        # Only DNS responses with answers
        if dns.qr != 1 or not dns.an:
            return

        src_ip = pkt[IP].src if pkt.haslayer(IP) else "unknown"

        # Check each answer record
        rr = dns.an
        while rr and rr.type != 0:
            if rr.type == 1:  # A record
                try:
                    domain = rr.rrname.decode().rstrip(".")
                    resolved_ip = rr.rdata

                    # DNS hijacking: domain now resolves to new IP
                    if self.track_changes and domain in self.dns_cache:
                        known_ips = self.dns_cache[domain]
                        if resolved_ip not in known_ips:
                            self.alerter.alert(
                                severity="HIGH",
                                event_type="dns_hijacking",
                                source_ip=src_ip,
                                destination=domain,
                                detail=f"{domain} now resolves to {resolved_ip} (previously: {', '.join(known_ips)})",
                                extra={"domain": domain, "new_ip": resolved_ip, "known_ips": list(known_ips)}
                            )
                            self.dns_cache[domain].add(resolved_ip)
                    else:
                        self.dns_cache[domain] = {resolved_ip}

                    # DNS tunneling detection: high entropy subdomain labels
                    labels = domain.split(".")
                    if len(labels) > 2:
                        subdomain = ".".join(labels[:-2])
                        entropy = shannon_entropy(subdomain)
                        if entropy > self.entropy_threshold:
                            self.alerter.alert(
                                severity="MEDIUM",
                                event_type="dns_tunneling_suspect",
                                source_ip=src_ip,
                                destination=domain,
                                detail=f"High entropy subdomain (entropy={entropy:.2f}): {domain}",
                                extra={"entropy": round(entropy, 2), "subdomain": subdomain}
                            )
                except Exception:
                    # Don't let a single malformed record kill the monitor,
                    # but surface the error instead of swallowing it silently.
                    logger.exception("Failed to process DNS A record")

            try:
                rr = rr.payload
            except Exception:
                break
