"""Config loader for NetSentinel."""
import yaml
from pathlib import Path

DEFAULTS = {
    "interface": "eth0",
    "log_file": "netsentinel.json",
    "thresholds": {
        "port_scan_ports": 15,
        "port_scan_window": 10,
        "icmp_flood_count": 50,
        "icmp_flood_window": 5,
    },
    "whitelist_ips": ["127.0.0.1", "::1"],
    "dns_monitoring": {
        "enabled": True,
        "track_changes": True,
        "entropy_threshold": 3.5,
    },
    "alerts": {"console": True, "log_file": True},
}


def load_config(path="config.yaml"):
    p = Path(path)
    if p.exists():
        with open(p) as f:
            user_cfg = yaml.safe_load(f) or {}
        # Deep merge user config over defaults
        cfg = DEFAULTS.copy()
        for k, v in user_cfg.items():
            if isinstance(v, dict) and k in cfg:
                cfg[k] = {**cfg[k], **v}
            else:
                cfg[k] = v
        return cfg
    return DEFAULTS.copy()
