#!/usr/bin/env python3
"""
NetSentinel - Real-Time Network Threat Monitor
Detects ARP spoofing, port scans, DNS anomalies, and ICMP floods.

Requires root/sudo for packet capture.
"""

import argparse
import json
import sys
from collections import defaultdict
from datetime import datetime
from pathlib import Path

from config import load_config
from alerter import Alerter
from monitors.arp_monitor import ARPMonitor
from monitors.portscan_monitor import PortScanMonitor
from monitors.dns_monitor import DNSMonitor
from monitors.icmp_monitor import ICMPMonitor


def run_summary(log_file):
    """Analyze the JSON log file and print statistics."""
    p = Path(log_file)
    if not p.exists():
        print(f"[!] Log file not found: {log_file}")
        sys.exit(1)

    events = []
    with open(p) as f:
        for line in f:
            line = line.strip()
            if line:
                try:
                    events.append(json.loads(line))
                except json.JSONDecodeError:
                    continue

    if not events:
        print("[*] No events logged yet.")
        return

    print(f"\n{'='*50}")
    print(f"NetSentinel Log Summary — {len(events)} total events")
    print(f"{'='*50}\n")

    by_type = defaultdict(int)
    by_severity = defaultdict(int)
    by_ip = defaultdict(int)

    for e in events:
        by_type[e.get("event_type", "unknown")] += 1
        by_severity[e.get("severity", "UNKNOWN")] += 1
        by_ip[e.get("source_ip", "unknown")] += 1

    print("By Severity:")
    for sev in ["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"]:
        if sev in by_severity:
            print(f"  {sev}: {by_severity[sev]}")

    print("\nBy Event Type:")
    for etype, count in sorted(by_type.items(), key=lambda x: -x[1]):
        print(f"  {etype}: {count}")

    print("\nTop Source IPs:")
    for ip, count in sorted(by_ip.items(), key=lambda x: -x[1])[:10]:
        print(f"  {ip}: {count} events")

    first = events[0].get("timestamp", "?")
    last = events[-1].get("timestamp", "?")
    print(f"\nTime range: {first} → {last}\n")


def main():
    parser = argparse.ArgumentParser(
        description="NetSentinel — Real-time network threat monitor",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  sudo python netsentinel.py                          # monitor on default interface
  sudo python netsentinel.py --interface wlan0        # specify interface
  sudo python netsentinel.py --config config.yaml     # use custom config
  python netsentinel.py --summary                     # analyze log file (no root needed)
        """
    )
    parser.add_argument("--interface", "-i", help="Network interface (overrides config)")
    parser.add_argument("--config", default="config.yaml", help="Config file path")
    parser.add_argument("--summary", action="store_true", help="Show log summary instead of capturing")
    args = parser.parse_args()

    cfg = load_config(args.config)
    if args.interface:
        cfg["interface"] = args.interface

    if args.summary:
        run_summary(cfg["log_file"])
        return

    # Check for root
    import os
    if os.geteuid() != 0:
        print("[!] NetSentinel requires root privileges for packet capture.")
        print("    Run with: sudo python netsentinel.py")
        sys.exit(1)

    try:
        from scapy.all import sniff
    except ImportError:
        print("[!] Scapy not installed. Run: pip install scapy")
        sys.exit(1)

    alerter = Alerter(cfg)
    alerter.banner()

    whitelist = cfg.get("whitelist_ips", [])
    thresholds = cfg.get("thresholds", {})
    dns_cfg = cfg.get("dns_monitoring", {})

    monitors = [
        ARPMonitor(alerter, whitelist=whitelist),
        PortScanMonitor(
            alerter,
            threshold=thresholds.get("port_scan_ports", 15),
            window=thresholds.get("port_scan_window", 10),
            whitelist=whitelist
        ),
        ICMPMonitor(
            alerter,
            threshold=thresholds.get("icmp_flood_count", 50),
            window=thresholds.get("icmp_flood_window", 5),
            whitelist=whitelist
        ),
    ]

    if dns_cfg.get("enabled", True):
        monitors.append(DNSMonitor(
            alerter,
            entropy_threshold=dns_cfg.get("entropy_threshold", 3.5),
            track_changes=dns_cfg.get("track_changes", True)
        ))

    def packet_callback(pkt):
        for monitor in monitors:
            try:
                monitor.process(pkt)
            except Exception:
                pass

    iface = cfg["interface"]
    alerter.info(f"Monitoring interface: {iface}")
    alerter.info(f"Logging to: {cfg['log_file']}")
    alerter.info("Press Ctrl+C to stop\n")

    try:
        sniff(iface=iface, prn=packet_callback, store=False)
    except KeyboardInterrupt:
        print("\n[*] Monitoring stopped.")
    except Exception as e:
        print(f"[!] Error: {e}")
        sys.exit(1)


if __name__ == "__main__":
    main()
