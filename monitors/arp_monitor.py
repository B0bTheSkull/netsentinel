"""ARP spoofing detection monitor."""
from scapy.layers.l2 import ARP


class ARPMonitor:
    def __init__(self, alerter, whitelist=None):
        self.alerter = alerter
        self.whitelist = set(whitelist or [])
        self.arp_table = {}  # ip -> mac

    def process(self, pkt):
        if not pkt.haslayer(ARP):
            return
        arp = pkt[ARP]
        # Only look at ARP replies (op=2)
        if arp.op != 2:
            return

        src_ip = arp.psrc
        src_mac = arp.hwsrc

        if src_ip in self.whitelist:
            return

        if src_ip in self.arp_table:
            known_mac = self.arp_table[src_ip]
            if known_mac != src_mac:
                self.alerter.alert(
                    severity="CRITICAL",
                    event_type="arp_spoofing",
                    source_ip=src_ip,
                    destination="LAN",
                    detail=f"ARP table poisoning: {src_ip} was {known_mac}, now claiming {src_mac}",
                    extra={"old_mac": known_mac, "new_mac": src_mac}
                )
        else:
            self.arp_table[src_ip] = src_mac
