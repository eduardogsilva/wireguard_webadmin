#!/usr/bin/env python3
"""
Reads JSON config files exported by Django and generates /etc/caddy/Caddyfile.

Expected input files in /caddy_json_export/:
  - wireguard_webadmin.json  (required, generated on container startup)
  - applications.json        (optional, exported from Django)
  - auth_policies.json       (optional, exported from Django)
  - routes.json              (optional, exported from Django)
"""

import json
import os
from urllib.parse import urlparse

JSON_DIR = os.environ.get("JSON_DIR", "/caddy_json_export")
CADDYFILE_PATH = os.environ.get("CADDYFILE_PATH", "/etc/caddy/Caddyfile")
AUTH_GATEWAY_INTERNAL_URL = os.environ.get("AUTH_GATEWAY_INTERNAL_URL", "http://wireguard-webadmin-auth-gateway:9091")
AUTH_GATEWAY_PORTAL_PATH = os.environ.get("AUTH_GATEWAY_EXTERNAL_PATH", "/auth-gateway")
AUTH_GATEWAY_CHECK_URI = "/auth/check"


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


def build_caddyfile(apps, auth_policies, routes):
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

    def handle_open(matcher):
        if matcher == "*":
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

    for app in apps:
        hosts = app.get("hosts", [])
        upstream = app.get("upstream", "")
        allow_invalid_cert = app.get("allow_invalid_cert", False)
        static_routes = app.get("static_routes", [])
        app_id = app.get("id", "")

        if not hosts or not upstream:
            continue

        base, upstream_path = split_upstream(upstream)

        lines.append(f"{', '.join(hosts)} {{")
        lines.append("  # Security: overwrite client-supplied forwarding headers with verified values")
        lines.append("  request_header X-Forwarded-For {remote_host}")
        lines.append("  request_header -X-Forwarded-Host")
        lines.append("")
        emit_auth_portal()

        for static_route in static_routes:
            path_prefix = static_route.get("path_prefix", "")
            root_dir = static_route.get("root", "")
            cache_control = static_route.get("cache_control", "")
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
            continue

        route_list = sorted(app_route_data.get("routes", []), key=lambda route: len(route.get("path_prefix", "")), reverse=True)
        for route in route_list:
            path_prefix = route.get("path_prefix", "/")
            policy_type = get_policy_type(route.get("policy"))
            matcher = f"{path_prefix}*"
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
            emit_protected_handle("*", base, upstream_path, allow_invalid_cert=allow_invalid_cert)
        lines.append("}")
        lines.append("")

    return "\n".join(lines)


def main():
    apps = collect_all_applications()
    auth_policies = load_json("auth_policies.json")
    routes = load_json("routes.json")

    caddyfile_content = build_caddyfile(apps, auth_policies, routes)
    os.makedirs(os.path.dirname(CADDYFILE_PATH), exist_ok=True)
    with open(CADDYFILE_PATH, "w", encoding="utf-8") as caddyfile:
        caddyfile.write(caddyfile_content)
    print(f"Caddyfile written to {CADDYFILE_PATH}")


if __name__ == "__main__":
    main()
