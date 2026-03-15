#!/usr/bin/env python3
"""
Reads JSON config files exported by Django and generates:
  - /etc/caddy/Caddyfile
  - /authelia_config/configuration.yml
  - /authelia_config/users_database.yml

Expected input files in /caddy_json_export/:
  - wireguard_webadmin.json  (required, generated on container startup)
  - applications.json        (optional, exported from Django)
  - auth_policies.json       (optional, exported from Django)
  - routes.json              (optional, exported from Django)
"""

import json
import os
import secrets
import string

import yaml

JSON_DIR = os.environ.get("JSON_DIR", "/caddy_json_export")
CADDYFILE_PATH = os.environ.get("CADDYFILE_PATH", "/etc/caddy/Caddyfile")
AUTHELIA_CONFIG_DIR = os.environ.get("AUTHELIA_CONFIG_DIR", "/authelia_config")
AUTHELIA_CONFIG_PATH = os.path.join(AUTHELIA_CONFIG_DIR, "configuration.yml")
AUTHELIA_USERS_PATH = os.path.join(AUTHELIA_CONFIG_DIR, "users_database.yml")
AUTHELIA_SECRETS_DIR = os.path.join(AUTHELIA_CONFIG_DIR, "secrets")

AUTHELIA_INTERNAL_URL = "http://wireguard-webadmin-authelia:9091"
AUTHELIA_PORTAL_PATH = "/authelia"


def load_json(filename):
    filepath = os.path.join(JSON_DIR, filename)
    if not os.path.exists(filepath):
        return None
    with open(filepath, "r", encoding="utf-8") as json_file:
        return json.load(json_file)


def generate_secret(length=64):
    alphabet = string.ascii_letters + string.digits
    return "".join(secrets.choice(alphabet) for char_index in range(length))


def get_or_create_secret(name):
    os.makedirs(AUTHELIA_SECRETS_DIR, exist_ok=True)
    secret_path = os.path.join(AUTHELIA_SECRETS_DIR, name)
    if os.path.exists(secret_path):
        with open(secret_path, "r", encoding="utf-8") as secret_file:
            return secret_file.read().strip()
    secret_value = generate_secret()
    with open(secret_path, "w", encoding="utf-8") as secret_file:
        secret_file.write(secret_value)
    return secret_value


def collect_all_applications():
    """Merge entries from wireguard_webadmin.json and applications.json."""
    apps = []

    webadmin_data = load_json("wireguard_webadmin.json")
    if webadmin_data:
        apps.extend(webadmin_data.get("entries", []))

    applications_data = load_json("applications.json")
    if applications_data:
        apps.extend(applications_data.get("entries", []))

    return apps


def build_caddyfile(apps, auth_policies, routes):
    lines = []
    has_authelia = auth_policies is not None
    policies = auth_policies.get("policies", {}) if has_authelia else {}

    def get_policy_type(policy_name):
        if policy_name and policy_name in policies:
            return policies[policy_name].get("policy_type", "bypass")
        return "bypass"

    for app in apps:
        app_id = app.get("id", "unknown")
        hosts = app.get("hosts", [])
        upstream = app.get("upstream", "")
        static_routes = app.get("static_routes", [])

        if not hosts or not upstream:
            continue

        host_list = ", ".join(hosts)
        lines.append(f"{host_list} {{")

        if has_authelia and app_id == "wireguard_webadmin":
            lines.append(f"  handle_path {AUTHELIA_PORTAL_PATH}/* {{")
            lines.append(f"    reverse_proxy {AUTHELIA_INTERNAL_URL}")
            lines.append(f"  }}")
            lines.append("")

        for static_route in static_routes:
            path_prefix = static_route.get("path_prefix", "")
            root_dir = static_route.get("root", "")
            strip_prefix = static_route.get("strip_prefix", "")
            cache_control = static_route.get("cache_control", "")

            lines.append(f"  handle_path {path_prefix}/* {{")
            lines.append(f"    root * {root_dir}")
            lines.append(f"    file_server")
            if cache_control:
                lines.append(f"    header Cache-Control \"{cache_control}\"")
            lines.append(f"  }}")
            lines.append("")

        app_routes = {}
        app_default_policy = None
        if routes:
            route_entries = routes.get("entries", {})
            if app_id in route_entries:
                app_route_data = route_entries[app_id]
                app_default_policy = app_route_data.get("default_policy")
                for route in app_route_data.get("routes", []):
                    app_routes[route.get("path_prefix", "")] = route.get("policy", "")

        default_policy_type = get_policy_type(app_default_policy)

        # When the default policy is deny, use handle blocks for specific
        # non-deny routes and a catch-all respond 403 at Caddy level,
        # avoiding an unnecessary Authelia round-trip.
        if has_authelia and default_policy_type == "deny":
            for path_prefix, policy_name in app_routes.items():
                ptype = get_policy_type(policy_name)
                if ptype == "bypass":
                    lines.append(f"  handle {path_prefix}/* {{")
                    lines.append(f"    reverse_proxy {upstream}")
                    lines.append(f"  }}")
                    lines.append("")
                elif ptype == "deny":
                    lines.append(f"  handle {path_prefix}/* {{")
                    lines.append(f"    respond 403")
                    lines.append(f"  }}")
                    lines.append("")
                else:
                    lines.append(f"  handle {path_prefix}/* {{")
                    lines.append(f"    forward_auth {AUTHELIA_INTERNAL_URL} {{")
                    lines.append(f"      uri {AUTHELIA_PORTAL_PATH}/api/authz/forward-auth")
                    lines.append(f"      copy_headers Remote-User Remote-Groups Remote-Name Remote-Email")
                    lines.append(f"    }}")
                    lines.append(f"    reverse_proxy {upstream}")
                    lines.append(f"  }}")
                    lines.append("")
            lines.append(f"  respond 403")
            lines.append(f"}}")
            lines.append("")
            continue

        # For bypass/protected default policy: emit explicit deny blocks for
        # any per-route deny entries before the forward_auth check.
        for path_prefix, policy_name in app_routes.items():
            if get_policy_type(policy_name) == "deny":
                lines.append(f"  handle {path_prefix}/* {{")
                lines.append(f"    respond 403")
                lines.append(f"  }}")
                lines.append("")

        needs_auth = False
        if has_authelia and auth_policies:
            if default_policy_type not in ("bypass", "deny"):
                needs_auth = True
            for path_prefix, policy_name in app_routes.items():
                if get_policy_type(policy_name) not in ("bypass", "deny"):
                    needs_auth = True

        if needs_auth:
            for path_prefix, policy_name in app_routes.items():
                if get_policy_type(policy_name) == "bypass":
                    lines.append(f"  @bypass_{_sanitize_id(path_prefix)} path {path_prefix}*")
                    lines.append(f"  skip_log @bypass_{_sanitize_id(path_prefix)}")
                    lines.append("")

            lines.append(f"  forward_auth {AUTHELIA_INTERNAL_URL} {{")
            lines.append(f"    uri {AUTHELIA_PORTAL_PATH}/api/authz/forward-auth")
            lines.append(f"    copy_headers Remote-User Remote-Groups Remote-Name Remote-Email")
            lines.append(f"  }}")
            lines.append("")

        lines.append(f"  reverse_proxy {upstream}")
        lines.append(f"}}")
        lines.append("")

    return "\n".join(lines)


def _sanitize_id(value):
    return value.strip("/").replace("/", "_").replace("-", "_")


def _collect_app_domains(apps, server_address):
    """Return session cookie entries for all unique app hostnames.

    Authelia v4.37+ requires a session.cookies entry for every domain managed
    via forward_auth. Without it, Authelia does not recognise the domain and
    may allow requests through regardless of the access_control policy.
    """
    seen = {server_address}
    cookies = [
        {
            "domain": server_address,
            "authelia_url": f"https://{server_address}{AUTHELIA_PORTAL_PATH}",
            "default_redirection_url": f"https://{server_address}",
        }
    ]
    for app in apps:
        for host in app.get("hosts", []):
            if host not in seen:
                seen.add(host)
                cookies.append({
                    "domain": host,
                    "authelia_url": f"https://{server_address}{AUTHELIA_PORTAL_PATH}",
                    "default_redirection_url": f"https://{server_address}",
                })
    return cookies


def build_authelia_config(auth_policies, routes, apps):
    server_address = os.environ.get("SERVER_ADDRESS", "localhost")

    jwt_secret = get_or_create_secret("jwt_secret")
    session_secret = get_or_create_secret("session_secret")
    storage_encryption_key = get_or_create_secret("storage_encryption_key")

    config = {
        "server": {
            "address": "tcp://0.0.0.0:9091",
        },
        "log": {
            "level": "info",
        },
        "identity_validation": {
            "reset_password": {
                "jwt_secret": jwt_secret,
            },
        },
        "authentication_backend": {
            "file": {
                "path": "/config/users_database.yml",
            },
        },
        "session": {
            "secret": session_secret,
            "cookies": _collect_app_domains(apps, server_address),
        },
        "storage": {
            "encryption_key": storage_encryption_key,
            "local": {
                "path": "/data/db.sqlite3",
            },
        },
        "notifier": {
            "filesystem": {
                "filename": "/data/notification.txt",
            },
        },
        "access_control": build_access_control_rules(auth_policies, routes, apps),
    }

    identity_providers = build_identity_providers(auth_policies, server_address)
    if identity_providers:
        config["identity_providers"] = identity_providers

    return config


def build_access_control_rules(auth_policies, routes, apps):
    if not auth_policies or not routes:
        return {"default_policy": "bypass", "rules": []}

    policies = auth_policies.get("policies", {})
    route_entries = routes.get("entries", {})

    host_map = {}
    for app in apps:
        app_id = app.get("id", "unknown")
        host_map[app_id] = app.get("hosts", [])

    rules = []

    for app_id, route_data in route_entries.items():
        app_hosts = host_map.get(app_id, [])
        if not app_hosts:
            continue

        domain_list = list(app_hosts)

        for route in route_data.get("routes", []):
            policy_name = route.get("policy", "")
            path_prefix = route.get("path_prefix", "")

            if policy_name not in policies:
                continue

            policy_data = policies[policy_name]
            policy_type = policy_data.get("policy_type", "bypass")

            if policy_type == "bypass":
                authelia_policy = "bypass"
            elif policy_type == "deny":
                authelia_policy = "deny"
            else:
                authelia_policy = "two_factor"

            rule = {
                "domain": domain_list,
                "policy": authelia_policy,
                "resources": [f"^{path_prefix}.*$"],
            }

            groups = policy_data.get("groups", [])
            if groups and authelia_policy not in ("bypass", "deny"):
                rule["subject"] = [f"group:{g}" for g in groups]

            rules.append(rule)

        default_policy_name = route_data.get("default_policy")
        if default_policy_name and default_policy_name in policies:
            default_policy_data = policies[default_policy_name]
            default_type = default_policy_data.get("policy_type", "bypass")

            if default_type == "bypass":
                authelia_default = "bypass"
            elif default_type == "deny":
                authelia_default = "deny"
            else:
                authelia_default = "two_factor"

            default_rule = {
                "domain": domain_list,
                "policy": authelia_default,
            }

            groups = default_policy_data.get("groups", [])
            if groups and authelia_default not in ("bypass", "deny"):
                default_rule["subject"] = [f"group:{g}" for g in groups]

            rules.append(default_rule)

    return {
        "default_policy": "two_factor" if not rules else "deny",
        "rules": rules,
    }


def build_identity_providers(auth_policies, server_address):
    if not auth_policies:
        return None

    auth_methods = auth_policies.get("auth_methods", {})
    oidc_clients = []

    for method_name, method in auth_methods.items():
        if method.get("type") != "oidc":
            continue

        client_id = method.get("client_id", "")
        client_secret = method.get("client_secret", "")
        if not client_id:
            continue

        client = {
            "client_id": client_id,
            "client_secret": client_secret,
            "authorization_policy": "two_factor",
            "redirect_uris": [
                f"https://{server_address}{AUTHELIA_PORTAL_PATH}/oidc/callback",
            ],
            "scopes": ["openid", "profile", "email", "groups"],
        }
        oidc_clients.append(client)

    if not oidc_clients:
        return None

    hmac_secret = get_or_create_secret("oidc_hmac_secret")

    return {
        "oidc": {
            "hmac_secret": hmac_secret,
            "clients": oidc_clients,
        },
    }


DUMMY_USER = {
    "_dummy_setup_user": {
        "disabled": True,
        "displayname": "Dummy Setup User",
        "password": "$argon2id$v=19$m=65536,t=3,p=4$Nklqa1J5a3ZweDhlZnNlUw$5D8WJ+sT20eXj1U10qNnS2Ew/M40B8v1/37X2b1lG0I",
        "email": "dummy@localhost",
    }
}

def build_users_database(auth_policies):
    if not auth_policies:
        return {"users": DUMMY_USER}

    users_data = auth_policies.get("users", {})
    groups_data = auth_policies.get("groups", {})

    user_groups = {}
    for group_name, group_info in groups_data.items():
        for username in group_info.get("users", []):
            if username not in user_groups:
                user_groups[username] = []
            user_groups[username].append(group_name)

    users = {}
    for username, user_info in users_data.items():
        user_entry = {
            "displayname": username,
            "email": user_info.get("email", f"{username}@localhost"),
            "groups": user_groups.get(username, []),
        }
        password_hash = user_info.get("password_hash", "")
        if password_hash:
            user_entry["password"] = password_hash

        users[username] = user_entry

    if not users:
        users = DUMMY_USER.copy()

    return {"users": users}


class _NoAliasDumper(yaml.SafeDumper):
    """YAML dumper that never emits anchors/aliases."""
    def ignore_aliases(self, data):
        return True


def write_yaml(filepath, data):
    os.makedirs(os.path.dirname(filepath), exist_ok=True)
    with open(filepath, "w", encoding="utf-8") as yaml_file:
        yaml.dump(data, yaml_file, Dumper=_NoAliasDumper, default_flow_style=False, allow_unicode=True, sort_keys=False)


def main():
    apps = collect_all_applications()
    auth_policies = load_json("auth_policies.json")
    routes = load_json("routes.json")

    caddyfile_content = build_caddyfile(apps, auth_policies, routes)
    os.makedirs(os.path.dirname(CADDYFILE_PATH), exist_ok=True)
    with open(CADDYFILE_PATH, "w", encoding="utf-8") as caddyfile:
        caddyfile.write(caddyfile_content)
    print(f"Caddyfile written to {CADDYFILE_PATH}")

    if auth_policies:
        authelia_config = build_authelia_config(auth_policies, routes, apps)
        write_yaml(AUTHELIA_CONFIG_PATH, authelia_config)
        print(f"Authelia configuration written to {AUTHELIA_CONFIG_PATH}")

        users_db = build_users_database(auth_policies)
        write_yaml(AUTHELIA_USERS_PATH, users_db)
        print(f"Authelia users database written to {AUTHELIA_USERS_PATH}")
    else:
        print("No auth_policies.json found, skipping Authelia config generation.")


if __name__ == "__main__":
    main()
