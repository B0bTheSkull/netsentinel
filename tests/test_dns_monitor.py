"""Tests for Shannon entropy and DNS hijack/tunnel detection."""
import math

import pytest
from scapy.layers.dns import DNS, DNSQR, DNSRR
from scapy.layers.inet import IP, UDP

from monitors.dns_monitor import shannon_entropy, DNSMonitor
from conftest import FakeAlerter


# ---- shannon_entropy ----

def test_entropy_empty_string_is_zero():
    assert shannon_entropy("") == 0


def test_entropy_uniform_single_char_is_zero():
    assert shannon_entropy("aaaa") == 0


def test_entropy_two_equal_symbols_is_one():
    assert shannon_entropy("ab") == pytest.approx(1.0)
    assert shannon_entropy("aabb") == pytest.approx(1.0)


def test_entropy_increases_with_diversity():
    low = shannon_entropy("aaaaaaaa")
    high = shannon_entropy("a1b2c3d4e5f6g7h8")
    assert high > low
    assert high == pytest.approx(4.0)


def test_entropy_matches_manual_calculation():
    # "abc" -> 3 symbols each 1/3 -> log2(3)
    assert shannon_entropy("abc") == pytest.approx(math.log2(3))


# ---- DNS hijack / tunnel detection ----

def _dns_response(domain, ip, src="192.168.1.1"):
    return (IP(src=src, dst="192.168.1.10") / UDP(sport=53, dport=12345) /
            DNS(qr=1, qd=DNSQR(qname=domain),
                an=DNSRR(rrname=domain, type="A", rdata=ip)))


def test_first_resolution_no_alert():
    a = FakeAlerter()
    mon = DNSMonitor(a)
    mon.process(_dns_response("bank.example.com", "1.2.3.4"))
    assert a.alerts == []
    assert "1.2.3.4" in mon.dns_cache["bank.example.com"]


def test_same_ip_repeated_no_alert():
    a = FakeAlerter()
    mon = DNSMonitor(a)
    mon.process(_dns_response("bank.example.com", "1.2.3.4"))
    mon.process(_dns_response("bank.example.com", "1.2.3.4"))
    assert a.alerts == []


def test_changed_ip_triggers_hijack_alert():
    a = FakeAlerter()
    mon = DNSMonitor(a)
    mon.process(_dns_response("bank.example.com", "1.2.3.4"))
    mon.process(_dns_response("bank.example.com", "6.6.6.6"))
    hijacks = [x for x in a.alerts if x["event_type"] == "dns_hijacking"]
    assert len(hijacks) == 1
    assert hijacks[0]["severity"] == "HIGH"
    assert "6.6.6.6" in mon.dns_cache["bank.example.com"]


def test_track_changes_disabled_skips_hijack():
    a = FakeAlerter()
    mon = DNSMonitor(a, track_changes=False)
    mon.process(_dns_response("bank.example.com", "1.2.3.4"))
    mon.process(_dns_response("bank.example.com", "6.6.6.6"))
    assert [x for x in a.alerts if x["event_type"] == "dns_hijacking"] == []


def test_high_entropy_subdomain_triggers_tunnel_alert():
    a = FakeAlerter()
    mon = DNSMonitor(a, entropy_threshold=3.5)
    # long random-looking label -> high entropy
    domain = "a1b2c3d4e5f6g7h8i9j0k1l2.tunnel.example.com"
    mon.process(_dns_response(domain, "1.2.3.4"))
    tunnels = [x for x in a.alerts if x["event_type"] == "dns_tunneling_suspect"]
    assert len(tunnels) == 1
    assert tunnels[0]["severity"] == "MEDIUM"


def test_low_entropy_subdomain_no_tunnel_alert():
    a = FakeAlerter()
    mon = DNSMonitor(a, entropy_threshold=3.5)
    mon.process(_dns_response("www.example.com", "1.2.3.4"))
    assert [x for x in a.alerts if x["event_type"] == "dns_tunneling_suspect"] == []


def test_non_dns_packet_ignored():
    a = FakeAlerter()
    mon = DNSMonitor(a)
    mon.process(IP(src="1.1.1.1", dst="2.2.2.2") / UDP())
    assert a.alerts == []
