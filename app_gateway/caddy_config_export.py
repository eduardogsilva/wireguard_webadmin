import json
import os

from app_gateway.models import (
    AccessPolicy, Application, ApplicationPolicy, RESERVED_APP_NAME
)
from gatekeeper.models import (
    AuthMethod, GatekeeperGroup, GatekeeperIPAddress, GatekeeperUser
)

POLICY_TYPE_MAP = {
    'public': 'bypass',
    'protected': 'protected',
    'deny': 'deny',
}


def build_applications_data():
    applications = Application.objects.exclude(name=RESERVED_APP_NAME).prefetch_related('hosts')
    entries = []
    for app in applications:
        entry = {
            'id': app.name,
            'name': app.display_name or app.name,
            'hosts': list(app.hosts.values_list('hostname', flat=True)),
            'upstream': app.upstream,
            'allow_invalid_cert': app.allow_invalid_cert,
        }
        entries.append(entry)
    return {'entries': entries}


def _build_auth_method_entry(method):
    entry = {'type': method.auth_type}

    if method.auth_type == 'local_password':
        entry['session_expiration_minutes'] = method.session_expiration_minutes

    elif method.auth_type == 'totp':
        entry['totp_secret'] = method.totp_secret

    elif method.auth_type == 'oidc':
        entry['session_expiration_minutes'] = method.session_expiration_minutes
        entry['provider'] = method.oidc_provider
        entry['client_id'] = method.oidc_client_id
        entry['client_secret'] = method.oidc_client_secret
        entry['allowed_domains'] = list(
            method.allowed_domains.values_list('domain', flat=True)
        )
        entry['allowed_emails'] = list(
            method.allowed_emails.values_list('email', flat=True)
        )

    elif method.auth_type == 'ip_address':
        rules = []
        for ip_entry in GatekeeperIPAddress.objects.filter(auth_method=method):
            rules.append({
                'address': str(ip_entry.address),
                'prefix_length': ip_entry.prefix_length,
                'action': ip_entry.action,
                'description': ip_entry.description,
            })
        entry['rules'] = rules

    return entry


def build_auth_policies_data():
    auth_methods = {}
    for method in AuthMethod.objects.all():
        auth_methods[method.name] = _build_auth_method_entry(method)

    groups = {}
    for group in GatekeeperGroup.objects.prefetch_related('users'):
        groups[group.name] = {
            'users': list(group.users.values_list('username', flat=True)),
        }

    users = {}
    for user in GatekeeperUser.objects.all():
        users[user.username] = {
            'email': user.email,
            'password_hash': user.password or '',
            'totp_secret': user.totp_secret,
        }

    policies = {}
    for policy in AccessPolicy.objects.prefetch_related('groups', 'methods'):
        policies[policy.name] = {
            'policy_type': POLICY_TYPE_MAP.get(policy.policy_type, policy.policy_type),
            'groups': list(policy.groups.values_list('name', flat=True)),
            'methods': list(policy.methods.values_list('name', flat=True)),
        }

    return {
        'auth_methods': auth_methods,
        'groups': groups,
        'users': users,
        'policies': policies,
    }


def build_routes_data():
    applications = (
        Application.objects
        .exclude(name=RESERVED_APP_NAME)
        .prefetch_related('routes__policy')
    )
    entries = {}
    for app in applications:
        try:
            app_policy = ApplicationPolicy.objects.get(application=app)
            default_policy = app_policy.default_policy.name
        except ApplicationPolicy.DoesNotExist:
            default_policy = None

        routes = []
        for route in app.routes.all().order_by('order', 'path_prefix'):
            routes.append({
                'id': route.name,
                'path_prefix': route.path_prefix,
                'policy': route.policy.name,
            })

        entry = {'routes': routes}
        if default_policy:
            entry['default_policy'] = default_policy

        entries[app.name] = entry

    return {'entries': entries}


def export_caddy_config(output_dir):
    os.makedirs(output_dir, exist_ok=True)

    file_map = {
        'applications.json': build_applications_data,
        'auth_policies.json': build_auth_policies_data,
        'routes.json': build_routes_data,
    }

    for filename, builder in file_map.items():
        filepath = os.path.join(output_dir, filename)
        with open(filepath, 'w', encoding='utf-8') as output_file:
            json.dump(builder(), output_file, indent=2)
            output_file.write('\n')
