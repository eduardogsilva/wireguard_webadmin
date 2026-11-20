import glob
import hashlib
import json
import os
from datetime import timedelta

from django.conf import settings
from django.utils import timezone
from django.utils.dateparse import parse_datetime

from app_gateway.caddy_config_export import (
    add_certificate_files, certificate_file_name, load_worker_export, read_exported_certificate
)
from cluster.models import ClusterSettings, WorkerStatus
from dns.functions import generate_dnsmasq_config
from dns.models import DNSFilterList
from firewall.tools import generate_firewall_script
from wireguard.models import WireGuardInstance
from wireguard_tools.functions import CLUSTER_WIREGUARD_CONFIG_DIR, WIREGUARD_CONFIG_DIR

DNSMASQ_CONFIG_DIR = '/etc/dnsmasq'
DNSMASQ_MAIN_CONFIG = 'wireguard_webadmin_dns.conf'

# Sections are applied by the node in this order. The firewall comes first because the WireGuard
# configuration runs wg-firewall.sh as PostUp of one of the instances, and certificates come before the
# gateway so the generated Caddyfile only references files that already exist.
SECTION_NAMES = ('firewall', 'wireguard', 'dns', 'settings', 'certificates', 'gateway')

# Large files (e.g. DNS filter lists) are only read and hashed again when they change on disk
_file_cache = {}


def _sha256(text):
    return hashlib.sha256(text.encode()).hexdigest()


def _read_file(path):
    file_stat = os.stat(path)
    cache_key = (file_stat.st_mtime_ns, file_stat.st_size)
    cached = _file_cache.get(path)
    if cached and cached['key'] == cache_key:
        return cached['content'], cached['sha256']
    with open(path, 'r', encoding='utf-8', errors='replace') as config_file:
        content = config_file.read()
    content_sha256 = _sha256(content)
    _file_cache[path] = {'key': cache_key, 'content': content, 'sha256': content_sha256}
    return content, content_sha256


class Section:
    def __init__(self):
        self.files = {}
        self.file_hashes = {}
        self.values = {}

    def add_file(self, filename, content, content_sha256=None):
        self.files[filename] = content
        self.file_hashes[filename] = content_sha256 or _sha256(content)

    @property
    def hash(self):
        fingerprint = json.dumps({'files': self.file_hashes, 'values': self.values}, sort_keys=True)
        return _sha256(fingerprint)

    def as_dict(self):
        return {'hash': self.hash, 'files': self.files, 'values': self.values}


def build_wireguard_section(worker):
    section = Section()
    if ClusterSettings.is_distributed():
        # Only the instances that run on this worker
        config_paths = [
            os.path.join(CLUSTER_WIREGUARD_CONFIG_DIR, f'wg{instance_id}.conf')
            for instance_id in WireGuardInstance.objects.filter(worker=worker).values_list('instance_id', flat=True)
        ]
    else:
        config_paths = glob.glob(os.path.join(WIREGUARD_CONFIG_DIR, 'wg[0-9]*.conf'))
    for config_path in sorted(config_paths):
        if not os.path.isfile(config_path):
            continue
        content, content_sha256 = _read_file(config_path)
        section.add_file(os.path.basename(config_path), content, content_sha256)
    return section


def build_firewall_section(worker):
    section = Section()
    section.add_file('wg-firewall.sh', generate_firewall_script(cluster_node=True, worker=worker))
    return section


def build_dns_section(worker):
    section = Section()
    for dns_list in DNSFilterList.objects.filter(enabled=True).order_by('uuid'):
        list_path = os.path.join(DNSMASQ_CONFIG_DIR, f'{dns_list.uuid}.conf')
        if os.path.isfile(list_path):
            content, content_sha256 = _read_file(list_path)
            section.add_file(os.path.basename(list_path), content, content_sha256)
    section.add_file(DNSMASQ_MAIN_CONFIG, generate_dnsmasq_config(cluster_node=True))
    return section


def build_settings_section(worker):
    section = Section()
    section.values = {
        'stats_sync_interval': settings.WIREGUARD_STATUS_CACHE_REFRESH_INTERVAL,
    }
    return section


EMPTY_GATEWAY_EXPORT = {
    'applications.json': {'entries': []},
    'auth_policies.json': {'auth_methods': {}, 'groups': {}, 'users': {}, 'policies': {}},
    'routes.json': {'entries': {}},
    'tls.json': {'hosts': {}, 'dns_credentials': {}},
}


def get_gateway_export(worker):
    """Configuration exported for the worker, with the certificate files currently available on the primary."""
    gateway_export = load_worker_export(worker) or json.loads(json.dumps(EMPTY_GATEWAY_EXPORT))
    add_certificate_files(gateway_export['tls.json'])
    return gateway_export


def build_certificates_section(worker):
    """Certificate and private key of every ACME host served by the worker, named after the certificate hash."""
    section = Section()
    for hostname, host_tls in sorted(get_gateway_export(worker)['tls.json']['hosts'].items()):
        if not host_tls.get('certificate_file'):
            continue
        certificate, private_key = read_exported_certificate(hostname)
        if not certificate or not private_key:
            continue
        file_name = certificate_file_name(certificate)
        section.add_file(f'{file_name}.crt', certificate)
        section.add_file(f'{file_name}.key', private_key)
    return section


def build_gateway_section(worker):
    section = Section()
    for file_name, data in get_gateway_export(worker).items():
        section.add_file(file_name, json.dumps(data, indent=2) + '\n')
    return section


SECTION_BUILDERS = {
    'firewall': build_firewall_section,
    'wireguard': build_wireguard_section,
    'dns': build_dns_section,
    'settings': build_settings_section,
    'certificates': build_certificates_section,
    'gateway': build_gateway_section,
}


def build_section(section_name, worker):
    return SECTION_BUILDERS[section_name](worker)


def build_manifest(worker):
    return {section_name: build_section(section_name, worker).hash for section_name in SECTION_NAMES}


CERTIFICATE_EXPIRATION_WARNING_DAYS = 14


def get_worker_warnings(worker):
    """Stopped services and certificates that are not trusted or expire soon, as reported by the worker."""
    try:
        worker_status = worker.workerstatus
    except WorkerStatus.DoesNotExist:
        return {'stopped_services': [], 'certificate_issues': []}

    stopped_services = sorted(
        service for service, state in (worker_status.services_status or {}).items() if state != 'running'
    )
    expiration_limit = timezone.now() + timedelta(days=CERTIFICATE_EXPIRATION_WARNING_DAYS)
    certificate_issues = []
    for hostname, certificate in sorted((worker_status.certificate_status or {}).items()):
        not_after = parse_datetime(certificate.get('not_after') or '')
        if certificate.get('status') not in ('trusted', 'untrusted'):
            certificate_issues.append(hostname)
        elif certificate.get('status') == 'trusted' and not_after and not_after < expiration_limit:
            certificate_issues.append(hostname)
    return {'stopped_services': stopped_services, 'certificate_issues': certificate_issues}


def get_worker_sync_state(worker, manifest=None):
    """
    Compare the hashes reported by the worker with the current ones.
    Returns {'state': 'synced'|'pending'|'error', 'sections': {name: {'state': ..., 'message': ...}}}.
    """
    manifest = manifest or build_manifest(worker)
    try:
        section_status = worker.workerstatus.section_status or {}
    except WorkerStatus.DoesNotExist:
        section_status = {}

    sections = {}
    for section_name, section_hash in manifest.items():
        reported = section_status.get(section_name) or {}
        if reported.get('hash') != section_hash:
            # A previous error is kept as information while the node retries with the new content
            sections[section_name] = {'state': 'pending', 'message': reported.get('message', '')}
        elif reported.get('status') == 'error':
            sections[section_name] = {'state': 'error', 'message': reported.get('message', '')}
        else:
            sections[section_name] = {'state': 'synced', 'message': ''}

    states = {section['state'] for section in sections.values()}
    if 'error' in states:
        state = 'error'
    elif 'pending' in states:
        state = 'pending'
    else:
        state = 'synced'
    return {'state': state, 'sections': sections}
