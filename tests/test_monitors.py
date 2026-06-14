"""Tests for port-scan, ICMP-flood and ARP-spoofing detection thresholds/state."""
from scapy.layers.inet import IP, TCP, ICMP
from scapy.layers.l2 import ARP

from monitors.portscan_monitor import PortScanMonitor
from monitors.icmp_monitor import ICMPMonitor
from monitors.arp_monitor import ARPMonitor
from conftest import FakeAlerter


def _syn(src, dport):
    return IP(src=src, dst="10.0.0.1") / TCP(dport=dport, flags="S")


# ---- PortScan ----

def test_portscan_below_threshold_no_alert():
    a = FakeAlerter()
    mon = PortScanMonitor(a, threshold=15, window=10)
    for port in range(10):
        mon.process(_syn("1.2.3.4", 1000 + port))
    assert a.alerts == []


def test_portscan_reaching_threshold_alerts_once():
    a = FakeAlerter()
    mon = PortScanMonitor(a, threshold=15, window=10)
    for port in range(20):
        mon.process(_syn("1.2.3.4", 1000 + port))
    scans = [x for x in a.alerts if x["event_type"] == "port_scan"]
    assert len(scans) == 1  # deduped
    assert scans[0]["severity"] == "HIGH"


def test_portscan_duplicate_ports_dont_count():
    a = FakeAlerter()
    mon = PortScanMonitor(a, threshold=15, window=10)
    for _ in range(30):
        mon.process(_syn("1.2.3.4", 80))  # same port repeatedly
    assert a.alerts == []


def test_portscan_whitelist_ignored():
    a = FakeAlerter()
    mon = PortScanMonitor(a, threshold=5, window=10, whitelist=["1.2.3.4"])
    for port in range(20):
        mon.process(_syn("1.2.3.4", 1000 + port))
    assert a.alerts == []


def test_portscan_non_syn_ignored():
    a = FakeAlerter()
    mon = PortScanMonitor(a, threshold=3, window=10)
    for port in range(20):
        # SYN+ACK is not a bare SYN
        mon.process(IP(src="1.2.3.4", dst="10.0.0.1") / TCP(dport=1000 + port, flags="SA"))
    assert a.alerts == []


# ---- ICMP ----

def _echo(src):
    return IP(src=src, dst="10.0.0.1") / ICMP(type=8)


def test_icmp_flood_threshold_alerts_once():
    a = FakeAlerter()
    mon = ICMPMonitor(a, threshold=50, window=5)
    for _ in range(60):
        mon.process(_echo("9.9.9.9"))
    floods = [x for x in a.alerts if x["event_type"] == "icmp_flood"]
    assert len(floods) == 1


def test_icmp_below_threshold_no_alert():
    a = FakeAlerter()
    mon = ICMPMonitor(a, threshold=50, window=5)
    for _ in range(10):
        mon.process(_echo("9.9.9.9"))
    assert a.alerts == []


def test_icmp_non_echo_ignored():
    a = FakeAlerter()
    mon = ICMPMonitor(a, threshold=2, window=5)
    for _ in range(10):
        mon.process(IP(src="9.9.9.9", dst="10.0.0.1") / ICMP(type=0))  # echo reply
    assert a.alerts == []


# ---- ARP ----

def _arp_reply(ip, mac):
    return ARP(op=2, psrc=ip, hwsrc=mac)


def test_arp_first_mapping_no_alert():
    a = FakeAlerter()
    mon = ARPMonitor(a)
    mon.process(_arp_reply("10.0.0.5", "aa:bb:cc:dd:ee:ff"))
    assert a.alerts == []
    assert mon.arp_table["10.0.0.5"] == "aa:bb:cc:dd:ee:ff"


def test_arp_mac_change_triggers_spoof_alert():
    a = FakeAlerter()
    mon = ARPMonitor(a)
    mon.process(_arp_reply("10.0.0.5", "aa:bb:cc:dd:ee:ff"))
    mon.process(_arp_reply("10.0.0.5", "11:22:33:44:55:66"))
    spoofs = [x for x in a.alerts if x["event_type"] == "arp_spoofing"]
    assert len(spoofs) == 1
    assert spoofs[0]["severity"] == "CRITICAL"


def test_arp_same_mac_no_alert():
    a = FakeAlerter()
    mon = ARPMonitor(a)
    mon.process(_arp_reply("10.0.0.5", "aa:bb:cc:dd:ee:ff"))
    mon.process(_arp_reply("10.0.0.5", "aa:bb:cc:dd:ee:ff"))
    assert a.alerts == []


def test_arp_request_ignored():
    a = FakeAlerter()
    mon = ARPMonitor(a)
    mon.process(ARP(op=1, psrc="10.0.0.5", hwsrc="aa:bb:cc:dd:ee:ff"))
    assert mon.arp_table == {}


def test_arp_whitelist_ignored():
    a = FakeAlerter()
    mon = ARPMonitor(a, whitelist=["10.0.0.5"])
    mon.process(_arp_reply("10.0.0.5", "aa:bb:cc:dd:ee:ff"))
    mon.process(_arp_reply("10.0.0.5", "11:22:33:44:55:66"))
    assert a.alerts == []
