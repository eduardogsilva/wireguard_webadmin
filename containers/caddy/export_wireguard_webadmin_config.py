#!/usr/bin/env python3
"""
Generates wireguard_webadmin.json from environment variables.

The output format matches the schema defined in config_example/wireguard_webadmin.json
and is intended to be processed by a separate configuration pipeline.
"""

import json
import os
import re
import sys

OUTPUT_FILE = os.environ.get(
    "OUTPUT_FILE",
    os.path.join(os.path.dirname(__file__), "config_files/wireguard_webadmin.json"),
)
OUTPUT_FILE_CADDY = "/caddy_json_export/wireguard_webadmin.json"

UPSTREAM = "wireguard-webadmin:8000"
STATIC_ROUTES = [
    {
        "path_prefix": "/static",
        "root": "/static",
        "strip_prefix": "/static",
        "cache_control": "public, max-age=3600",
    }
]

IPV4_RE = re.compile(r"^\d+\.\d+\.\d+\.\d+$")
HOSTNAME_RE = re.compile(
    r"^[A-Za-z0-9]([A-Za-z0-9\-]*[A-Za-z0-9])?(\.[A-Za-z0-9]([A-Za-z0-9\-]*[A-Za-z0-9])?)*$"
)


def normalize_host(raw: str) -> str:
    """Strip scheme, path, and port from a host string."""
    raw = raw.strip()
    for scheme in ("https://", "http://"):
        if raw.startswith(scheme):
            raw = raw[len(scheme):]
    raw = raw.split("/")[0]

    # IPv6 bracketed address with port: [::1]:8080 → [::1]
    if raw.startswith("[") and "]:" in raw:
        raw = raw.rsplit(":", 1)[0]
        return raw

    # Plain IPv4 or hostname with port: host:8080 → host (not IPv6)
    if raw.count(":") == 1:
        raw = raw.split(":")[0]

    return raw


def is_ip(host: str) -> bool:
    """Return True if host is an IPv4 address or an IPv6 address."""
    if IPV4_RE.match(host):
        return True
    if host.startswith("[") or ":" in host:
        return True
    return False


def is_valid_hostname(host: str) -> bool:
    """Return True only for proper DNS hostnames (no IPs)."""
    if not host:
        return False
    if is_ip(host):
        return False
    return bool(HOSTNAME_RE.match(host))


def collect_hosts() -> list:
    """Build the ordered, deduplicated list of hosts from environment variables."""
    seen = set()
    hosts = []

    def add_host(host: str) -> None:
        normalized = normalize_host(host)
        if normalized and normalized not in seen:
            seen.add(normalized)
            hosts.append(normalized)

    primary = os.environ.get("SERVER_ADDRESS", "").strip()
    primary_normalized = normalize_host(primary)

    if not is_valid_hostname(primary_normalized):
        print(
            f"Error: SERVER_ADDRESS must be a valid hostname, not an IP address. "
            f"Received: {primary!r}",
            file=sys.stderr,
        )
        sys.exit(1)

    add_host(primary)

    for extra in os.environ.get("EXTRA_ALLOWED_HOSTS", "").split(","):
        extra = extra.strip()
        if not extra:
            continue
        normalized = normalize_host(extra)
        # Skip IPs and localhost-style entries (handled by TLS internally)
        if is_ip(normalized) or normalized in ("localhost",) or normalized.endswith(".localhost"):
            continue
        add_host(extra)

    if not hosts:
        print("Error: no valid hostnames were collected.", file=sys.stderr)
        sys.exit(1)

    return hosts


def build_config(hosts: list) -> dict:
    return {
        "entries": [
            {
                "id": "wireguard_webadmin",
                "name": "WireGuard WebAdmin",
                "hosts": hosts,
                "upstream": UPSTREAM,
                "static_routes": STATIC_ROUTES,
            }
        ]
    }


def _write_config(filepath, config):
    os.makedirs(os.path.dirname(filepath), exist_ok=True)
    with open(filepath, "w", encoding="utf-8") as output_file:
        json.dump(config, output_file, indent=2)
        output_file.write("\n")
    print(f"Config written to {filepath}")


def main() -> None:
    hosts = collect_hosts()
    config = build_config(hosts)

    _write_config(OUTPUT_FILE, config)

    caddy_export_dir = os.path.dirname(OUTPUT_FILE_CADDY)
    if os.path.isdir(caddy_export_dir):
        _write_config(OUTPUT_FILE_CADDY, config)


if __name__ == "__main__":
    main()

