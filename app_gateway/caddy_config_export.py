import hashlib
import json
import os
import shutil

from django.conf import settings
from django.contrib import messages
from django.utils.translation import gettext as _

from app_gateway.models import (
    AccessPolicy, Application, ApplicationHost, ApplicationPolicy, RESERVED_APP_NAME
)
from cluster.models import Worker
from gatekeeper.models import (
    AuthMethod, GatekeeperGroup, GatekeeperIPAddress, GatekeeperUser
)

POLICY_TYPE_MAP = {
    'public': 'bypass',
    'protected': 'protected',
    'deny': 'deny',
}

# Written by the Caddy container of the primary server, read-only for Django
CERTIFICATE_EXPORT_DIR = '/caddy_cert_export'
ACME_CERTIFICATE_TYPES = ('http_challenge', 'dns_challenge')


def get_served_applications(worker=None):
    """Applications published by the primary server (worker=None) or by a cluster worker."""
    applications = Application.objects.prefetch_related('hosts', 'workers')
    if worker is not None:
        applications = applications.exclude(name=RESERVED_APP_NAME)
    return [application for application in applications if application.is_served_by(worker)]


def certificate_file_name(certificate):
    return hashlib.sha256(certificate.encode()).hexdigest()


def read_exported_certificate(hostname):
    """Return (certificate, private_key) exported for a hostname, or (None, None)."""
    if '/' in hostname or hostname in ('', '.', '..'):
        return None, None
    certificate_dir = os.path.join(CERTIFICATE_EXPORT_DIR, hostname)
    try:
        with open(os.path.join(certificate_dir, 'certificate.crt'), 'r', encoding='utf-8') as certificate_file:
            certificate = certificate_file.read()
        with open(os.path.join(certificate_dir, 'certificate.key'), 'r', encoding='utf-8') as key_file:
            private_key = key_file.read()
    except OSError:
        return None, None
    return certificate, private_key


def build_applications_data(worker=None):
    entries = []
    for app in get_served_applications(worker):
        if app.name == RESERVED_APP_NAME:
            continue
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


def build_auth_policies_data(worker=None):
    # Policies, methods, groups and users are referenced by name, so every server receives all of them
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


def build_routes_data(worker=None):
    entries = {}
    for app in get_served_applications(worker):
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


def build_tls_data(worker=None):
    """
    On the primary server every ACME certificate is issued, including the ones of applications that are only
    served by cluster workers (certificate_only), and certificates used by workers are exported. Workers never
    issue ACME certificates: they receive the exported certificate (certificate_file) or use the internal CA.
    """
    hosts = {}
    dns_credentials = {}
    served_application_ids = {application.pk for application in get_served_applications(worker)}

    application_hosts = ApplicationHost.objects.select_related('dns_credential', 'application').prefetch_related(
        'application__workers'
    )
    for application_host in application_hosts:
        application = application_host.application
        hostname = application_host.hostname.lower()
        is_acme = application_host.certificate_type in ACME_CERTIFICATE_TYPES
        host_entry = {
            'certificate_type': application_host.certificate_type,
            'certificate_fallback': application_host.certificate_fallback,
        }

        if worker is not None:
            if application.pk in served_application_ids:
                hosts[hostname] = host_entry
            continue

        served_by_workers = application.name != RESERVED_APP_NAME and application.served_by_workers
        if application.pk not in served_application_ids and not (served_by_workers and is_acme):
            continue
        host_entry['certificate_generation'] = application_host.certificate_generation
        if served_by_workers and is_acme:
            host_entry['export_certificate'] = True
            if application.pk not in served_application_ids:
                host_entry['certificate_only'] = True
        dns_credential = application_host.dns_credential
        if application_host.certificate_type == 'dns_challenge' and dns_credential:
            host_entry['dns_credential'] = dns_credential.name
            dns_credentials[dns_credential.name] = {
                'provider': dns_credential.provider,
                'credentials': dns_credential.credentials,
            }
        hosts[hostname] = host_entry

    return {
        'hosts': hosts,
        'dns_credentials': dns_credentials,
    }


CADDY_EXPORT_DIR = '/caddy_json_export/'

EXPORT_FILES = {
    'applications.json': build_applications_data,
    'auth_policies.json': build_auth_policies_data,
    'routes.json': build_routes_data,
    'tls.json': build_tls_data,
}


# Cluster workers follow the configuration exported for them, so changes are only published by an export
WORKER_EXPORT_DIR_NAME = 'cluster'


def get_worker_export_dir(output_dir, worker):
    return os.path.join(output_dir, WORKER_EXPORT_DIR_NAME, str(worker.uuid))


def _write_export_files(target_dir, worker=None):
    os.makedirs(target_dir, exist_ok=True)
    for filename, builder in EXPORT_FILES.items():
        filepath = os.path.join(target_dir, filename)
        with open(filepath, 'w', encoding='utf-8') as output_file:
            json.dump(builder(worker), output_file, indent=2)
            output_file.write('\n')


def export_caddy_config(output_dir):
    os.makedirs(output_dir, exist_ok=True)
    workers = list(Worker.objects.all())
    for worker in workers:
        _write_export_files(get_worker_export_dir(output_dir, worker), worker)

    workers_export_dir = os.path.join(output_dir, WORKER_EXPORT_DIR_NAME)
    if os.path.isdir(workers_export_dir):
        worker_uuids = {str(worker.uuid) for worker in workers}
        for worker_dir_name in os.listdir(workers_export_dir):
            if worker_dir_name not in worker_uuids:
                shutil.rmtree(os.path.join(workers_export_dir, worker_dir_name), ignore_errors=True)

    # The primary server is written last: its files are the ones Caddy and the auth-gateway watch
    _write_export_files(output_dir)


def load_exported_files(target_dir):
    """Return {filename: data} from an export directory, or None when it is missing or incomplete."""
    exported_files = {}
    for filename in EXPORT_FILES:
        try:
            with open(os.path.join(target_dir, filename), 'r', encoding='utf-8') as exported_file:
                exported_files[filename] = json.load(exported_file)
        except (OSError, ValueError):
            return None
    return exported_files


def load_worker_export(worker, output_dir=None):
    return load_exported_files(get_worker_export_dir(output_dir or CADDY_EXPORT_DIR, worker))


def add_certificate_files(tls_data):
    """Point the ACME hosts of a worker to the certificates currently exported by the primary server."""
    for hostname, host_tls in tls_data.get('hosts', {}).items():
        if host_tls.get('certificate_type') not in ACME_CERTIFICATE_TYPES:
            continue
        certificate, private_key = read_exported_certificate(hostname)
        host_tls['certificate_file'] = certificate_file_name(certificate) if certificate and private_key else ''
    return tls_data


def _export_differs(target_dir, worker=None):
    exported_files = load_exported_files(target_dir)
    if exported_files is None:
        return True
    # Round-trip through JSON so the comparison matches what export_caddy_config writes
    for filename, builder in EXPORT_FILES.items():
        if json.loads(json.dumps(builder(worker))) != exported_files[filename]:
            return True
    return False


def has_pending_export(output_dir):
    """Return True when the current configuration differs from the files last exported to output_dir."""
    if _export_differs(output_dir):
        return True
    return any(_export_differs(get_worker_export_dir(output_dir, worker), worker) for worker in Worker.objects.all())


def caddy_export_pending():
    return settings.CADDY_ENABLED and has_pending_export(CADDY_EXPORT_DIR)


def apply_caddy_config():
    """Export the configuration read by Caddy, the auth-gateway and the cluster workers."""
    export_caddy_config(CADDY_EXPORT_DIR)
    if settings.DEBUG:
        export_caddy_config(os.path.join(settings.BASE_DIR, 'containers', 'caddy', 'config_files'))


def auto_apply_caddy_config(request):
    if not settings.AUTO_APPLY or not settings.CADDY_ENABLED:
        return False
    apply_caddy_config()
    messages.info(request, _('Gateway configuration applied automatically.'))
    return True
