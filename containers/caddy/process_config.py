#!/usr/bin/env python3
"""
Reads JSON config files exported by Django and generates /etc/caddy/Caddyfile.

Expected input files in /caddy_json_export/:
  - wireguard_webadmin.json  (required, generated on container startup)
  - applications.json        (optional, exported from Django)
  - auth_policies.json       (optional, exported from Django)
  - routes.json              (optional, exported from Django)
  - tls.json                 (optional, exported from Django)
"""

import json
import os
import re
from urllib.parse import urlparse

JSON_DIR = os.environ.get("JSON_DIR", "/caddy_json_export")
CADDYFILE_PATH = os.environ.get("CADDYFILE_PATH", "/etc/caddy/Caddyfile")
AUTH_GATEWAY_INTERNAL_URL = os.environ.get("AUTH_GATEWAY_INTERNAL_URL", "http://wireguard-webadmin-auth-gateway:9091")
AUTH_GATEWAY_PORTAL_PATH = os.environ.get("AUTH_GATEWAY_EXTERNAL_PATH", "/auth-gateway")
AUTH_GATEWAY_CHECK_URI = "/auth/check"
CERTIFICATE_TYPES = ("self_signed", "http_challenge", "dns_challenge")
DEFAULT_CERTIFICATE_TYPE = "http_challenge"
ACME_DNS_RESOLVERS = "1.1.1.1 1.0.0.1"
# Set by entrypoint.sh when the generated Caddyfile fails validation
DISABLE_DNS_CHALLENGE = os.environ.get("DISABLE_DNS_CHALLENGE", "") == "1"
AUTH_IDENTITY_HEADERS = (
    "X-Auth-User",
    "X-Auth-Email",
    "X-Auth-Groups",
    "X-Auth-Factors",
    "X-Auth-Policy",
)


def load_json(filename):
    filepath = os.path.join(JSON_DIR, filename)
    if not os.path.exists(filepath):
        return None
    with open(filepath, "r", encoding="utf-8") as json_file:
        return json.load(json_file)


def collect_all_applications():
    apps = []

    webadmin_data = load_json("wireguard_webadmin.json")
    if webadmin_data:
        apps.extend(webadmin_data.get("entries", []))

    applications_data = load_json("applications.json")
    if applications_data:
        apps.extend(applications_data.get("entries", []))

    return apps


def split_upstream(upstream):
    """Return (base_url, upstream_path) where base_url has no path component.
    Upstreams without an explicit http(s):// scheme are returned as-is with no path."""
    if not upstream.startswith("http://") and not upstream.startswith("https://"):
        return upstream, ""
    parsed = urlparse(upstream)
    base = f"{parsed.scheme}://{parsed.netloc}"
    path = parsed.path.rstrip("/")
    return base, path


def _safe_value(val: str) -> str:
    """Strip characters that would break or inject into a Caddyfile directive."""
    return re.sub(r"[\r\n\x00]", "", val)


def _quote_value(val) -> str:
    escaped = _safe_value(str(val)).replace("\\", "\\\\").replace('"', '\\"')
    return f'"{escaped}"'


def _safe_identifier(val: str) -> str:
    return re.sub(r"[^A-Za-z0-9_]", "", str(val))


def get_host_tls(host, tls_data):
    """Return (certificate_type, dns_credential_name) for a host. Hosts not listed use the HTTP challenge."""
    host_tls = tls_data.get("hosts", {}).get(host.lower(), {})
    certificate_type = host_tls.get("certificate_type", DEFAULT_CERTIFICATE_TYPE)
    if certificate_type not in CERTIFICATE_TYPES:
        certificate_type = DEFAULT_CERTIFICATE_TYPE

    dns_credential = None
    if certificate_type == "dns_challenge":
        dns_credential = host_tls.get("dns_credential")
        if DISABLE_DNS_CHALLENGE or dns_credential not in tls_data.get("dns_credentials", {}):
            certificate_type = DEFAULT_CERTIFICATE_TYPE
            dns_credential = None
    return certificate_type, dns_credential


def group_hosts_by_tls(hosts, tls_data):
    """Hosts sharing the same certificate settings are served by the same site block."""
    groups = {}
    for host in hosts:
        groups.setdefault(get_host_tls(host, tls_data), []).append(host)
    return groups.items()


def build_caddyfile(apps, auth_policies, routes, tls_data=None):
    tls_data = tls_data or {}
    policies = auth_policies.get("policies", {}) if auth_policies else {}
    route_entries = routes.get("entries", {}) if routes else {}
    lines = []

    def get_policy_type(policy_name):
        if policy_name and policy_name in policies:
            return policies[policy_name].get("policy_type", "bypass")
        return "deny"

    def emit_auth_portal():
        lines.append(f"  handle_path {AUTH_GATEWAY_PORTAL_PATH}/* {{")
        lines.append(f"    reverse_proxy {AUTH_GATEWAY_INTERNAL_URL}")
        lines.append("  }")
        lines.append("")

    def emit_tls(certificate_type, dns_credential):
        if certificate_type == "self_signed":
            lines.append("  tls internal")
            lines.append("")
            return

        lines.append("  tls {")
        if certificate_type == "dns_challenge":
            dns_credential_data = tls_data["dns_credentials"][dns_credential]
            provider = _safe_identifier(dns_credential_data.get("provider", ""))
            lines.append("    issuer acme {")
            lines.append(f"      dns {provider} {{")
            for field_name, field_value in dns_credential_data.get("credentials", {}).items():
                lines.append(f"        {_safe_identifier(field_name)} {_quote_value(field_value)}")
            lines.append("      }")
            lines.append(f"      resolvers {ACME_DNS_RESOLVERS}")
            lines.append("    }")
        else:
            lines.append("    issuer acme")
        # Fall back to the internal CA when the ACME certificate cannot be issued
        lines.append("    issuer internal")
        lines.append("  }")
        lines.append("")

    def emit_identity_header_sanitization(indent="  "):
        for header_name in AUTH_IDENTITY_HEADERS:
            lines.append(f"{indent}request_header -{header_name}")

    def emit_encoded_slash_block():
        # Reject paths containing encoded slashes in any depth of percent-encoding:
        #   %2f        = /
        #   %252f      = %2f (double-encoded, decodes to / on second pass)
        #   %25252f    = triple-encoded, etc.
        # Caddy's path matcher does not decode percent-encoding, so /%2fadmin would
        # NOT match path /admin and would fall through to the default (potentially
        # bypass) handler even though some upstreams decode it to /admin.
        lines.append("  @encoded_slash {")
        lines.append("    path_regexp (?i)%(?:25)*2f")
        lines.append("  }")
        lines.append("  handle @encoded_slash {")
        lines.append("    respond 400")
        lines.append("  }")
        lines.append("")

    def emit_route_matcher(matcher_name, path_prefix):
        matcher_name = re.sub(r"[^A-Za-z0-9_]", "_", matcher_name)
        normalized_prefix = path_prefix.strip().rstrip("/") or "/"
        if not normalized_prefix.startswith("/"):
            normalized_prefix = f"/{normalized_prefix}"
        if normalized_prefix == "/":
            return None
        lines.append(f"  @{matcher_name} {{")
        lines.append(f"    path {normalized_prefix} {normalized_prefix}/*")
        lines.append("  }")
        lines.append("")
        return f"@{matcher_name}"

    def handle_open(matcher=None):
        if not matcher:
            return "  handle {"
        return f"  handle {matcher} {{"

    def emit_reverse_proxy(base, upstream_path, indent="    ", allow_invalid_cert=False):
        if upstream_path:
            lines.append(f"{indent}rewrite * {upstream_path}{{uri}}")
        if allow_invalid_cert:
            lines.append(f"{indent}reverse_proxy {base} {{")
            lines.append(f"{indent}  transport http {{")
            lines.append(f"{indent}    tls_insecure_skip_verify")
            lines.append(f"{indent}  }}")
            lines.append(f"{indent}}}")
        else:
            lines.append(f"{indent}reverse_proxy {base}")

    def emit_protected_handle(path_matcher, base, upstream_path, allow_invalid_cert=False):
        lines.append(handle_open(path_matcher))
        lines.append(f"    forward_auth {AUTH_GATEWAY_INTERNAL_URL} {{")
        lines.append(f"      uri {AUTH_GATEWAY_CHECK_URI}")
        lines.append("      copy_headers X-Auth-User X-Auth-Email X-Auth-Groups X-Auth-Factors X-Auth-Policy")
        lines.append("    }")
        emit_reverse_proxy(base, upstream_path, allow_invalid_cert=allow_invalid_cert)
        lines.append("  }")
        lines.append("")

    def emit_site_block(app, hosts, certificate_type, dns_credential):
        upstream = app.get("upstream", "")
        # tls_insecure_skip_verify is only valid for https upstreams
        allow_invalid_cert = app.get("allow_invalid_cert", False) and upstream.startswith("https://")
        static_routes = app.get("static_routes", [])
        app_id = app.get("id", "")

        base, upstream_path = split_upstream(upstream)

        safe_hosts = [_safe_value(h) for h in hosts]
        lines.append(f"{', '.join(safe_hosts)} {{")
        emit_tls(certificate_type, dns_credential)
        lines.append("  # Security: overwrite client-supplied forwarding headers with verified values")
        lines.append("  request_header X-Forwarded-For {http.request.remote.host}")
        lines.append("  request_header -X-Forwarded-Host")
        emit_identity_header_sanitization()
        lines.append("")
        emit_encoded_slash_block()
        emit_auth_portal()

        for static_route in static_routes:
            path_prefix = _safe_value(static_route.get("path_prefix", ""))
            root_dir = _safe_value(static_route.get("root", ""))
            cache_control = _safe_value(static_route.get("cache_control", ""))
            lines.append(f"  handle_path {path_prefix}/* {{")
            lines.append(f"    root * {root_dir}")
            lines.append("    file_server")
            if cache_control:
                lines.append(f"    header Cache-Control \"{cache_control}\"")
            lines.append("  }")
            lines.append("")

        app_route_data = route_entries.get(app_id)
        if app_route_data is None:
            emit_reverse_proxy(base, upstream_path, indent="  ", allow_invalid_cert=allow_invalid_cert)
            lines.append("}")
            lines.append("")
            return

        route_list = sorted(app_route_data.get("routes", []), key=lambda route: len(route.get("path_prefix", "")), reverse=True)
        for route_index, route in enumerate(route_list):
            path_prefix = route.get("path_prefix", "/")
            policy_type = get_policy_type(route.get("policy"))
            matcher = emit_route_matcher(f"route_{app_id}_{route_index}", path_prefix)
            if policy_type == "bypass":
                lines.append(handle_open(matcher))
                emit_reverse_proxy(base, upstream_path, allow_invalid_cert=allow_invalid_cert)
                lines.append("  }")
                lines.append("")
            elif policy_type == "deny":
                lines.append(handle_open(matcher))
                lines.append("    respond 403")
                lines.append("  }")
                lines.append("")
            else:
                emit_protected_handle(matcher, base, upstream_path, allow_invalid_cert=allow_invalid_cert)

        default_policy_type = get_policy_type(app_route_data.get("default_policy"))
        if default_policy_type == "bypass":
            emit_reverse_proxy(base, upstream_path, indent="  ", allow_invalid_cert=allow_invalid_cert)
        elif default_policy_type == "deny":
            lines.append("  respond 403")
        else:
            emit_protected_handle(None, base, upstream_path, allow_invalid_cert=allow_invalid_cert)
        lines.append("}")
        lines.append("")

    for app in apps:
        hosts = app.get("hosts", [])
        if not hosts or not app.get("upstream", ""):
            continue

        for (certificate_type, dns_credential), group_hosts in group_hosts_by_tls(hosts, tls_data):
            emit_site_block(app, group_hosts, certificate_type, dns_credential)

    return "\n".join(lines)


def main():
    apps = collect_all_applications()
    auth_policies = load_json("auth_policies.json")
    routes = load_json("routes.json")
    tls_data = load_json("tls.json")

    caddyfile_content = build_caddyfile(apps, auth_policies, routes, tls_data)
    os.makedirs(os.path.dirname(CADDYFILE_PATH), exist_ok=True)
    with open(CADDYFILE_PATH, "w", encoding="utf-8") as caddyfile:
        caddyfile.write(caddyfile_content)
    print(f"Caddyfile written to {CADDYFILE_PATH}")


if __name__ == "__main__":
    main()
