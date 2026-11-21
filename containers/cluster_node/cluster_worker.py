import glob
import hashlib
import ipaddress
import json
import logging
import os
import re
import socket
import ssl
import subprocess
import tempfile
import time
from datetime import datetime, timezone

import requests

logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)

MASTER_SERVER_ADDRESS = os.environ.get('MASTER_SERVER_ADDRESS', '')
TOKEN = os.environ.get('TOKEN', '')
WORKER_VERSION = 14
REQUEST_TIMEOUT = 30
MANIFEST_INTERVAL = 60
DEFAULT_STATS_INTERVAL = 60

WIREGUARD_DIR = '/etc/wireguard'
FIREWALL_SCRIPT = os.path.join(WIREGUARD_DIR, 'wg-firewall.sh')
DNS_DIR = '/etc/dnsmasq'
DNS_MAIN_CONFIG = 'wireguard_webadmin_dns.conf'
# Only mounted when the node runs the App Gateway (cluster_node-gateway.yml)
GATEWAY_DIR = '/caddy_json_export'
CERTIFICATES_DIR = '/caddy_certificates'
GATEWAY_FILES = ('applications.json', 'auth_policies.json', 'routes.json', 'tls.json')
# Sessions ended from the WireGuard WebAdmin, sent by primary servers that support it
GATEWAY_OPTIONAL_FILES = ('revoked_sessions.json',)
# Active sessions published by the auth-gateway
GATEWAY_SESSIONS_FILE = os.path.join(GATEWAY_DIR, 'state', 'sessions.json')
CERTIFICATE_FILE_PATTERN = re.compile(r'^[a-f0-9]{64}\.(crt|key)$')
CADDY_ADMIN_URL = 'http://127.0.0.1:2019/config/'
AUTH_GATEWAY_URL = 'http://cluster-node-auth-gateway:9091/'
INTERNAL_CA_NAME = 'Caddy Local Authority'
FIREWALL_CHAINS = (
    ('nat', 'WGWADM_POSTROUTING'),
    ('nat', 'WGWADM_PREROUTING'),
    ('filter', 'WGWADM_FORWARD'),
    ('filter', 'WGWADM_ROUTE_POLICY'),
)


class SectionError(Exception):
    pass


def run_command(command, check=True):
    result = subprocess.run(command, capture_output=True, text=True)
    if check and result.returncode != 0:
        raise SectionError(f"{' '.join(command)}: {(result.stderr or result.stdout).strip()}")
    return result


def interface_is_up(interface):
    return run_command(['wg', 'show', interface], check=False).returncode == 0


def sync_interface_routes(interface):
    """
    Bring the IPv4 routes of a running interface in line with its allowed IPs, as wg-quick does on start.
    wg syncconf only updates the peers. Default routes (/0) are left to wg-quick.
    """
    allowed_networks = set()
    for line in run_command(['wg', 'show', interface, 'allowed-ips']).stdout.splitlines():
        for value in line.split()[1:]:
            try:
                network = ipaddress.IPv4Network(value, strict=False)
            except ValueError:
                continue
            if network.prefixlen:
                allowed_networks.add(network)
    allowed_networks = sorted(allowed_networks, key=lambda network: network.prefixlen)

    errors = []
    for network in allowed_networks:
        if run_command(['ip', '-4', 'route', 'show', 'dev', interface, 'match', str(network)], check=False).stdout.strip():
            continue
        # replace instead of add: the network may still be routed to another instance it was moved from
        result = run_command(['ip', '-4', 'route', 'replace', str(network), 'dev', interface], check=False)
        if result.returncode != 0:
            errors.append(f'{network}: {result.stderr.strip()}')

    for route in run_command(['ip', '-o', '-4', 'route', 'show', 'dev', interface], check=False).stdout.splitlines():
        fields = route.split()
        if not fields or 'kernel' in fields:
            continue
        try:
            route_network = ipaddress.IPv4Network(fields[0], strict=False)
        except ValueError:
            continue
        # Only routes that no allowed IP covers are removed: the interface drops their traffic anyway
        if any(route_network.subnet_of(network) for network in allowed_networks):
            continue
        result = run_command(['ip', '-4', 'route', 'delete', str(route_network), 'dev', interface], check=False)
        if result.returncode != 0:
            errors.append(f'{route_network}: {result.stderr.strip()}')
    if errors:
        raise SectionError(f"{interface} routes: {'; '.join(errors)}")

def interface_section(config):
    """Return the [Interface] part of a WireGuard config, used to decide between syncconf and restart."""
    return config.split('[Peer]', 1)[0].strip()


def read_file(path):
    try:
        with open(path, 'r', encoding='utf-8') as config_file:
            return config_file.read()
    except FileNotFoundError:
        return None


def write_file(path, content, mode=0o600, in_place=False):
    if in_place:
        with open(path, 'w', encoding='utf-8') as config_file:
            config_file.write(content)
        os.chmod(path, mode)
        return
    temp_path = f'{path}.tmp'
    with open(temp_path, 'w', encoding='utf-8') as config_file:
        config_file.write(content)
    os.chmod(temp_path, mode)
    os.replace(temp_path, path)


def wireguard_status():
    result = run_command(['wg', 'show', 'all', 'dump'], check=False)
    if result.returncode != 0:
        return {}

    data = {}
    # Peer lines: interface, public_key, preshared_key, endpoint, allowed_ips, latest_handshake, rx, tx, keepalive
    for line in result.stdout.strip().splitlines():
        parts = line.split('\t')
        if len(parts) < 9:
            continue
        interface, peer_public_key, endpoint, allowed_ips = parts[0], parts[1], parts[3], parts[4]
        data.setdefault(interface, {})[peer_public_key] = {
            'allowed-ips': [ip for ip in allowed_ips.split(',') if ip] if allowed_ips else [],
            'latest-handshakes': parts[5] or '',
            'transfer': {'tx': int(parts[7] or 0), 'rx': int(parts[6] or 0)},
            'endpoints': endpoint or '',
        }
    return data


def gateway_enabled():
    return os.path.isdir(GATEWAY_DIR) and os.path.isdir(CERTIFICATES_DIR)


def http_service_is_running(url):
    try:
        requests.get(url, timeout=3)
        return True
    except requests.RequestException:
        return False


def _parse_not_after(value):
    return datetime.strptime(value, '%b %d %H:%M:%S %Y %Z').replace(tzinfo=timezone.utc).isoformat()


def _fetch_certificate(hostname, verify):
    if verify:
        context = ssl.create_default_context()
    else:
        context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
        context.check_hostname = False
        context.verify_mode = ssl.CERT_NONE
    with socket.create_connection(('127.0.0.1', 443), timeout=3) as raw_socket:
        with context.wrap_socket(raw_socket, server_hostname=hostname) as tls_socket:
            return tls_socket.getpeercert() if verify else tls_socket.getpeercert(binary_form=True)


def inspect_certificate(hostname):
    """Same checks as app_gateway/certificate_status.py on the primary server, against the local Caddy."""
    try:
        certificate = _fetch_certificate(hostname, verify=True)
        issuer = dict(field[0] for field in certificate.get('issuer', ()))
        return {
            'status': 'trusted',
            'issuer': issuer.get('organizationName') or issuer.get('commonName') or '',
            'not_after': _parse_not_after(certificate['notAfter']),
        }
    except ssl.SSLCertVerificationError:
        pass
    except (OSError, ValueError):
        return {'status': 'unavailable', 'issuer': '', 'not_after': None}

    try:
        certificate_der = _fetch_certificate(hostname, verify=False)
        result = subprocess.run(
            ['openssl', 'x509', '-inform', 'DER', '-noout', '-issuer', '-enddate', '-nameopt', 'RFC2253'],
            input=certificate_der, capture_output=True, timeout=5,
        )
    except (OSError, ValueError, subprocess.SubprocessError):
        return {'status': 'unavailable', 'issuer': '', 'not_after': None}
    issuer = ''
    not_after = None
    for line in result.stdout.decode(errors='replace').splitlines():
        if line.startswith('issuer='):
            parts = dict(part.split('=', 1) for part in line[len('issuer='):].split(',') if '=' in part)
            issuer = INTERNAL_CA_NAME if INTERNAL_CA_NAME in line else parts.get('O') or parts.get('CN') or ''
        elif line.startswith('notAfter='):
            not_after = _parse_not_after(line[len('notAfter='):])
    return {'status': 'untrusted', 'issuer': issuer, 'not_after': not_after}


def dns_is_running():
    # dnsmasq always listens on loopback when it is restricted to specific interfaces. The DNS container pauses
    # for a few seconds while reloading, so a missing answer is retried before reporting it as stopped.
    query = b'\x12\x34\x01\x00\x00\x01\x00\x00\x00\x00\x00\x00\x09localhost\x00\x00\x01\x00\x01'
    for attempt in range(4):
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as dns_socket:
            dns_socket.settimeout(2)
            try:
                dns_socket.sendto(query, ('127.0.0.1', 53))
                dns_socket.recvfrom(512)
                return True
            except OSError:
                pass
        time.sleep(1)
    return False


class ClusterNodeAgent:
    def __init__(self):
        self.base_url = f"{MASTER_SERVER_ADDRESS.rstrip('/')}/api/cluster/v2"
        self.session = requests.Session()
        self.session.headers.update({
            'Authorization': f'Bearer {TOKEN}',
            'X-Worker-Version': str(WORKER_VERSION),
        })
        # Nothing is persisted: after a restart interfaces and firewall rules are gone, so every section is applied again
        self.applied_hashes = {}
        self.stats_interval = DEFAULT_STATS_INTERVAL
        self.wireguard_active = False
        # Hash of the last gateway sessions accepted by the primary server: they are only sent when they change
        self.sent_sessions_hash = None

    def request(self, method, path, **kwargs):
        try:
            return self.session.request(method, f'{self.base_url}/{path}', timeout=REQUEST_TIMEOUT, **kwargs)
        except requests.RequestException as error:
            logger.error('Request to %s failed: %s', path, error)
            return None

    # Section handlers

    def apply_firewall(self, section):
        content = section['files'].get('wg-firewall.sh')
        if content is None:
            raise SectionError('wg-firewall.sh missing from section')
        write_file(FIREWALL_SCRIPT, content, mode=0o700)
        run_command(['bash', FIREWALL_SCRIPT])

    def apply_wireguard(self, section):
        desired_files = {
            filename: content for filename, content in section['files'].items()
            if filename.startswith('wg') and filename.endswith('.conf') and '/' not in filename
        }
        errors = []

        for config_path in glob.glob(os.path.join(WIREGUARD_DIR, 'wg[0-9]*.conf')):
            filename = os.path.basename(config_path)
            if filename in desired_files:
                continue
            interface = filename[:-len('.conf')]
            if interface_is_up(interface):
                run_command(['wg-quick', 'down', interface], check=False)
            os.remove(config_path)
            logger.info('Removed WireGuard interface %s', interface)

        for filename, content in sorted(desired_files.items()):
            interface = filename[:-len('.conf')]
            config_path = os.path.join(WIREGUARD_DIR, filename)
            previous_content = read_file(config_path)
            write_file(config_path, content)
            try:
                if not interface_is_up(interface):
                    run_command(['wg-quick', 'up', interface])
                    logger.info('Started WireGuard interface %s', interface)
                elif previous_content is None or interface_section(previous_content) != interface_section(content):
                    run_command(['wg-quick', 'down', interface], check=False)
                    run_command(['wg-quick', 'up', interface])
                    logger.info('Restarted WireGuard interface %s', interface)
                elif previous_content != content:
                    self.sync_peers(interface, config_path)
                    logger.info('Synchronized peers of WireGuard interface %s', interface)
            except SectionError as error:
                errors.append(str(error))
                # Back to the content actually applied, so the next attempt sees the change again
                if previous_content is not None:
                    write_file(config_path, previous_content)

        self.wireguard_active = True
        if errors:
            raise SectionError('; '.join(errors))

    @staticmethod
    def sync_peers(interface, config_path):
        stripped_config = run_command(['wg-quick', 'strip', config_path]).stdout
        with tempfile.NamedTemporaryFile('w', suffix='.conf', delete=False) as stripped_file:
            stripped_file.write(stripped_config)
        try:
            run_command(['wg', 'syncconf', interface, stripped_file.name])
        finally:
            os.remove(stripped_file.name)
        sync_interface_routes(interface)

    def apply_dns(self, section):
        files = section['files']
        if DNS_MAIN_CONFIG not in files:
            raise SectionError(f'{DNS_MAIN_CONFIG} missing from section')
        os.makedirs(DNS_DIR, exist_ok=True)
        for filename, content in files.items():
            if filename != DNS_MAIN_CONFIG and '/' not in filename:
                write_file(os.path.join(DNS_DIR, filename), content, mode=0o644)
        for config_path in glob.glob(os.path.join(DNS_DIR, '*.conf')):
            if os.path.basename(config_path) not in files:
                os.remove(config_path)
        # Written last and in place: the DNS container watches this file with inotify to reload
        write_file(os.path.join(DNS_DIR, DNS_MAIN_CONFIG), files[DNS_MAIN_CONFIG], mode=0o644, in_place=True)

    def apply_settings(self, section):
        self.stats_interval = int(section['values'].get('stats_sync_interval', DEFAULT_STATS_INTERVAL))

    def apply_certificates(self, section):
        if not gateway_enabled():
            return
        files = {
            filename: content for filename, content in section['files'].items()
            if CERTIFICATE_FILE_PATTERN.match(filename)
        }
        for filename, content in files.items():
            certificate_path = os.path.join(CERTIFICATES_DIR, filename)
            if read_file(certificate_path) != content:
                write_file(certificate_path, content, mode=0o600)
        for certificate_path in glob.glob(os.path.join(CERTIFICATES_DIR, '*')):
            if os.path.basename(certificate_path) not in files:
                os.remove(certificate_path)

    def apply_gateway(self, section):
        if not gateway_enabled():
            return
        for filename in GATEWAY_FILES:
            if filename not in section['files']:
                raise SectionError(f'{filename} missing from section')
        for filename in GATEWAY_FILES + GATEWAY_OPTIONAL_FILES:
            if filename in section['files']:
                write_file(os.path.join(GATEWAY_DIR, filename), section['files'][filename], mode=0o644)

    SECTION_HANDLERS = {
        'firewall': apply_firewall,
        'wireguard': apply_wireguard,
        'dns': apply_dns,
        'settings': apply_settings,
        'certificates': apply_certificates,
        'gateway': apply_gateway,
    }

    # Main loop

    def shutdown_wireguard(self):
        if not self.wireguard_active:
            return
        logger.warning('Shutting down WireGuard interfaces and firewall rules')
        for config_path in glob.glob(os.path.join(WIREGUARD_DIR, 'wg[0-9]*.conf')):
            run_command(['wg-quick', 'down', os.path.basename(config_path)[:-len('.conf')]], check=False)
        for table, chain in FIREWALL_CHAINS:
            run_command(['iptables', '-t', table, '-F', chain], check=False)
        self.applied_hashes.pop('wireguard', None)
        self.applied_hashes.pop('firewall', None)
        self.wireguard_active = False

    def sync_configuration(self):
        response = self.request('GET', 'manifest/')
        if response is None:
            return True
        if response.status_code == 403:
            logger.error('Token rejected by the primary server. Stopping.')
            self.shutdown_wireguard()
            return False
        if response.status_code == 400:
            logger.warning('Primary server refused this worker: %s', response.json().get('message', ''))
            self.shutdown_wireguard()
            return True
        if response.status_code != 200:
            logger.error('Unexpected manifest response: HTTP %s', response.status_code)
            return True

        manifest = response.json().get('sections', {})
        reports = {}
        for section_name, section_hash in manifest.items():
            if section_name not in self.SECTION_HANDLERS or self.applied_hashes.get(section_name) == section_hash:
                continue
            section_response = self.request('GET', f'section/{section_name}/')
            if section_response is None or section_response.status_code != 200:
                continue
            section = section_response.json()
            try:
                self.SECTION_HANDLERS[section_name](self, section)
                self.applied_hashes[section_name] = section['hash']
                reports[section_name] = {'hash': section['hash'], 'status': 'ok'}
                logger.info('Section %s applied', section_name)
            except (SectionError, OSError, ValueError) as error:
                # Forget the last applied content: the next version must be applied and reported even if it
                # is identical to the one that was applied before the failure
                self.applied_hashes.pop(section_name, None)
                reports[section_name] = {'hash': section['hash'], 'status': 'error', 'message': str(error)}
                logger.error('Section %s failed: %s', section_name, error)

        if reports:
            # Services are reported with the periodic stats: right after a DNS change dnsmasq is still reloading
            self.request('POST', 'report/', json={'sections': reports})
        return True

    @staticmethod
    def services_status():
        services = {'dnsmasq': 'running' if dns_is_running() else 'stopped'}
        if gateway_enabled():
            services['caddy'] = 'running' if http_service_is_running(CADDY_ADMIN_URL) else 'stopped'
            services['auth_gateway'] = 'running' if http_service_is_running(AUTH_GATEWAY_URL) else 'stopped'
        return services

    @staticmethod
    def certificates_status():
        try:
            with open(os.path.join(GATEWAY_DIR, 'tls.json'), 'r', encoding='utf-8') as tls_file:
                hosts = json.load(tls_file).get('hosts', {})
        except (OSError, ValueError):
            return {}
        return {hostname: inspect_certificate(hostname) for hostname in sorted(hosts)}

    @staticmethod
    def gateway_sessions():
        """Sessions published by the auth-gateway and their hash, or (None, None) when not available."""
        content = read_file(GATEWAY_SESSIONS_FILE)
        if content is None:
            return None, None
        try:
            sessions = json.loads(content).get('sessions')
        except (ValueError, AttributeError):
            return None, None
        if not isinstance(sessions, list):
            return None, None
        return sessions, hashlib.sha256(content.encode()).hexdigest()

    def send_stats(self):
        report = {
            'wireguard_status': wireguard_status(),
            'services': self.services_status(),
        }
        sessions_hash = None
        if gateway_enabled():
            report['certificates'] = self.certificates_status()
            sessions, sessions_hash = self.gateway_sessions()
            if sessions_hash and sessions_hash != self.sent_sessions_hash:
                report['gateway_sessions'] = sessions
        response = self.request('POST', 'report/', json=report)
        if 'gateway_sessions' in report and response is not None and response.status_code == 200:
            self.sent_sessions_hash = sessions_hash

    @staticmethod
    def publish_network_namespace():
        # Containers sharing this network namespace (DNS, Caddy) restart themselves when it changes
        network_namespace = os.readlink('/proc/self/ns/net')
        for directory in (DNS_DIR, GATEWAY_DIR):
            if os.path.isdir(directory):
                write_file(os.path.join(directory, '.netns_owner'), network_namespace + '\n', mode=0o644)

    def run(self):
        logger.info('Cluster node agent %s starting', WORKER_VERSION)
        self.publish_network_namespace()
        self.wireguard_active = True
        self.shutdown_wireguard()

        last_manifest = 0
        last_stats = 0
        while True:
            now = time.monotonic()
            if now - last_manifest >= MANIFEST_INTERVAL or not last_manifest:
                last_manifest = now
                if not self.sync_configuration():
                    break
            if now - last_stats >= self.stats_interval:
                last_stats = now
                self.send_stats()
            time.sleep(1)

        while True:
            time.sleep(3600)


if __name__ == '__main__':
    if not MASTER_SERVER_ADDRESS or not TOKEN:
        logger.error('MASTER_SERVER_ADDRESS and TOKEN must be set')
    else:
        ClusterNodeAgent().run()
