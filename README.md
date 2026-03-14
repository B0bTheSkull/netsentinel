# NetSentinel

> **Real-time network threat detection for your homelab and beyond.**
> Catches ARP spoofing, port scans, DNS hijacking, and ICMP floods as they happen — not after the fact.

![Python](https://img.shields.io/badge/python-3.8%2B-blue?style=flat-square&logo=python)
![Requires Root](https://img.shields.io/badge/requires-root-red?style=flat-square)
![License](https://img.shields.io/badge/license-MIT-green?style=flat-square)
![Scapy](https://img.shields.io/badge/built%20with-Scapy-orange?style=flat-square)

---

## What It Detects

| Threat | Detection Method | Severity |
|--------|-----------------|----------|
| **ARP Spoofing** | IP→MAC mapping changes mid-session | CRITICAL |
| **Port Scan** | SYN packets to N+ ports in sliding window | HIGH |
| **ICMP Flood** | Echo requests exceeding threshold | HIGH |
| **DNS Hijacking** | Domain suddenly resolves to new IP | HIGH |
| **DNS Tunneling** | High-entropy subdomain labels (C2/exfil) | MEDIUM |

---

## Installation

```bash
git clone https://github.com/B0bTheSkull/netsentinel.git
cd netsentinel
pip install -r requirements.txt
```

> **Note:** Packet capture requires root/sudo. The `--summary` mode for log analysis does not.

---

## Usage

```bash
# Monitor default interface (from config.yaml)
sudo python netsentinel.py

# Specify a different interface
sudo python netsentinel.py --interface wlan0

# Use a custom config file
sudo python netsentinel.py --config my_config.yaml

# Analyze the event log (no root needed)
python netsentinel.py --summary
```

---

## Configuration

Edit `config.yaml` to tune thresholds and behavior:

```yaml
interface: "eth0"
log_file: "netsentinel.json"

thresholds:
  port_scan_ports: 15      # ports hit in scan_window seconds = alert
  port_scan_window: 10     # window in seconds
  icmp_flood_count: 50     # ICMP packets in icmp_flood_window seconds
  icmp_flood_window: 5

whitelist_ips:
  - "127.0.0.1"
  - "10.0.0.1"             # your router

dns_monitoring:
  enabled: true
  track_changes: true
  entropy_threshold: 3.5   # higher = less sensitive to DNS tunneling
```

---

## Example Alerts

```
14:32:01 [CRITICAL] ARP SPOOFING | 192.168.1.55 → LAN | ARP table poisoning: 192.168.1.1 was aa:bb:cc:dd:ee:ff, now claiming 11:22:33:44:55:66
14:32:44 [HIGH] PORT SCAN | 203.0.113.45 → 192.168.1.10 | Port scan detected: 22 ports in 10s
14:33:01 [HIGH] ICMP FLOOD | 10.0.0.200 → 192.168.1.10 | ICMP flood: 87 echo requests in 5s
14:35:12 [HIGH] DNS HIJACKING | 8.8.8.8 → legitimate-bank.com | legitimate-bank.com now resolves to 185.220.101.77 (previously: 93.184.216.34)
14:36:05 [MEDIUM] DNS TUNNELING SUSPECT | 8.8.8.8 → xKf93mQpL7nR2vWs.c2domain.com | High entropy subdomain (entropy=4.21)
```

---

## Log Format

All events are written to `netsentinel.json` as newline-delimited JSON:

```json
{
  "timestamp": "2024-06-14T14:32:01.123456",
  "severity": "CRITICAL",
  "event_type": "arp_spoofing",
  "source_ip": "192.168.1.55",
  "destination": "LAN",
  "detail": "ARP table poisoning: 192.168.1.1 was aa:bb:cc:dd:ee:ff, now claiming 11:22:33:44:55:66",
  "old_mac": "aa:bb:cc:dd:ee:ff",
  "new_mac": "11:22:33:44:55:66"
}
```

---

## Log Summary

```bash
python netsentinel.py --summary
```

```
==================================================
NetSentinel Log Summary — 47 total events
==================================================

By Severity:
  CRITICAL: 2
  HIGH: 31
  MEDIUM: 14

By Event Type:
  port_scan: 28
  arp_spoofing: 2
  dns_tunneling_suspect: 14
  icmp_flood: 3

Top Source IPs:
  203.0.113.45: 19 events
  185.220.101.77: 12 events
```

---

## Roadmap

- [ ] Slack/Discord webhook alerting
- [ ] Passive OS fingerprinting
- [ ] PCAP capture on alert trigger
- [ ] Web dashboard (Flask)
- [ ] `systemd` service file for always-on monitoring

---

## License

MIT — see [LICENSE](LICENSE)
