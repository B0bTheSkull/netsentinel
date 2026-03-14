---
title: "I Got Paranoid About My Homelab Network. So I Built a Monitor."
date: 2024-07-08
tags: [networking, blue-team, scapy, python, homelab, arp-spoofing]
excerpt: "After setting up a homelab I started wondering — what's actually happening on my network? Who's probing what? Are my VMs talking to things they shouldn't be? I built NetSentinel to find out."
---

# I Got Paranoid About My Homelab Network. So I Built a Monitor.

It started with a question I couldn't answer: *what's actually happening on my network right now?*

I'd been running a homelab for a while — a few VMs, a Raspberry Pi, a NAS, the usual setup. And I realized I had zero visibility into what was going on at the network layer. Sure, I could check `netstat` on individual machines, but I had no bird's-eye view. No way to see if one of my VMs was doing something sketchy. No way to know if someone on my local network was ARP poisoning my router.

So I built **NetSentinel** — a real-time network monitor using Python and Scapy that watches for the stuff that matters.

## The Threat Model

Before writing a line of code, I thought about what I actually wanted to detect. For a homelab (and for most small networks), the threats I care about fall into four categories:

**ARP Spoofing**: This is the classic LAN attack. ARP has no authentication — anyone on the network can send an ARP reply claiming that a given IP address belongs to their MAC address. If an attacker does this convincingly, they can intercept traffic between any two hosts on the network. Man-in-the-middle, trivially.

**Port Scanning**: If something is scanning my network — either an external host that got past the firewall or a compromised internal host — I want to know about it. Port scans have a distinctive signature: lots of SYN packets to many different ports from one source IP in a short time window.

**DNS Hijacking and Tunneling**: DNS is weirdly undermonitored. A domain that suddenly resolves to a different IP than it used to is worth investigating. And attackers love DNS for covert channels — you can exfiltrate data by encoding it in subdomain labels, which most firewalls let through without inspection.

**ICMP Floods**: Basic, but worth detecting. Either someone's stress-testing or you've got a DoS situation starting.

## How It Works

NetSentinel uses Scapy's `sniff()` function to capture packets off the wire and route them through a set of modular monitors. Each monitor handles one threat type independently, which makes it easy to add new ones later.

### ARP Spoofing Detection

The ARP monitor maintains an IP→MAC mapping table. Every time it sees an ARP reply (opcode 2), it checks whether the claimed MAC address matches what it already knows for that IP. If a device that's been responding as `aa:bb:cc:dd:ee:ff` for IP `192.168.1.1` suddenly starts claiming it's `11:22:33:44:55:66`, that's a CRITICAL alert.

```python
if src_ip in self.arp_table:
    known_mac = self.arp_table[src_ip]
    if known_mac != src_mac:
        self.alerter.alert(severity="CRITICAL", event_type="arp_spoofing", ...)
```

The first time I tested this with a tool like `arpspoof`, it caught it immediately. That was a satisfying moment.

### Port Scan Detection

The port scan monitor tracks SYN packets (TCP flag `SYN=1, ACK=0`) per source IP using a sliding time window. If a single IP hits more than the configured threshold of unique destination ports within the window, it fires.

The sliding window is implemented simply: for each packet, we prune the tracker to only keep entries within the last N seconds, then check the count. No complex data structures needed.

### DNS Analysis

This one was the most interesting to build. The DNS monitor listens for DNS response packets and does two things:

1. **Change detection**: tracks which IP addresses each domain has resolved to historically. If a domain resolves to a new IP, it flags it as possible DNS hijacking.

2. **Entropy analysis**: DNS tunneling tools encode data in subdomain labels. Random or base64-encoded data has high Shannon entropy — much higher than real words or hostnames. If a subdomain's entropy exceeds the threshold (default 3.5 bits), it gets flagged.

Shannon entropy is a simple calculation: for each character, compute its frequency, then sum `-p * log2(p)` across all characters. Normal hostnames like `api.example.com` score around 2.5. Something like `xKf93mQpL7nR2vWs.example.com` scores above 4.0.

## Running It

```bash
# Requires root for raw packet capture
sudo python netsentinel.py --interface eth0

# Check the log without capturing
python netsentinel.py --summary
```

The real-time output is color-coded: CRITICAL in bright red, HIGH in red, MEDIUM in yellow. The `--summary` mode is handy for reviewing what happened overnight.

## What I Found Running It on My Homelab

Honestly? More than I expected.

Within the first 24 hours, I saw port scans from one of my Raspberry Pis that had an old version of Home Assistant on it. It was apparently doing some kind of network discovery that looked exactly like a scan from NetSentinel's perspective. That was a useful false positive to tune out — I whitelisted it and updated the Pi.

I also saw some interesting DNS traffic. Nothing that crossed the entropy threshold for tunneling, but a few domains I didn't recognize resolving to IPs that looked off. Turned out to be telemetry from a smart TV. Still, it was good to know.

No real attacks on the homelab, thankfully. But I feel significantly better having visibility now than I did before. And the next time something weird does happen, I'll have a log of exactly what the network was doing.

## What's Next

I want to add webhook alerting so I can get notified on Discord when something triggers. I also want to add a PCAP capture feature — when an alert fires, automatically save the last N seconds of packets to a file for later analysis. That would make incident response much easier.

The code is on GitHub if you want to run it yourself. Just remember: packet capture requires root, and you should only monitor networks you own or have permission to monitor.

---

*Code: [B0bTheSkull/netsentinel](https://github.com/B0bTheSkull/netsentinel)*
