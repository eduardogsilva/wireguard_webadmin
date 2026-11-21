import json
import os
import tempfile
from unittest.mock import patch

from django.contrib.auth.models import User
from django.test import TestCase, override_settings
from django.utils import timezone

from api.models import WireguardStatusCache
from api.views import func_concatenate_cluster_wireguard_status_cache
from app_gateway import caddy_config_export
from app_gateway.caddy_config_export import certificate_file_name, export_caddy_config
from app_gateway.models import Application, ApplicationHost, DnsChallengeCredential
from cluster import sync
from cluster.forms import ClusterSettingsForm
from cluster.models import ClusterSettings, Worker, WorkerStatus
from dns.models import DNSSettings
from firewall.forms import FirewallRuleForm
from firewall.models import FirewallRule, FirewallSettings, RedirectRule
from firewall.tools import generate_firewall_script
from user_manager.models import UserAcl
from wireguard.models import Peer, PeerAllowedIP, WireGuardInstance
from wireguard_tools.functions import get_config_servers
from wireguard_tools.tests import load_cluster_worker
from wireguard_tools.views import export_wireguard_configuration, generate_peer_config

FAKE_CERTIFICATE = '-----BEGIN CERTIFICATE-----\nfake\n-----END CERTIFICATE-----\n'
FAKE_PRIVATE_KEY = '-----BEGIN PRIVATE KEY-----\nfake\n-----END PRIVATE KEY-----\n'


class ClusterTestMixin:
    """Isolated directories for the files read and written by the cluster sync and the Caddy export."""

    def setUp(self):
        super().setUp()
        self.temp_dir = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp_dir.cleanup)
        self.wireguard_dir = os.path.join(self.temp_dir.name, 'wireguard')
        self.dnsmasq_dir = os.path.join(self.temp_dir.name, 'dnsmasq')
        self.export_dir = os.path.join(self.temp_dir.name, 'caddy_json_export')
        self.certificate_export_dir = os.path.join(self.temp_dir.name, 'caddy_cert_export')
        for directory in (self.wireguard_dir, self.dnsmasq_dir, self.export_dir, self.certificate_export_dir):
            os.makedirs(directory)
        with open(os.path.join(self.wireguard_dir, 'wg0.conf'), 'w', encoding='utf-8') as config_file:
            config_file.write('[Interface]\nListenPort = 51820\n')

        for target, value in (
            ('cluster.sync.WIREGUARD_CONFIG_DIR', self.wireguard_dir),
            ('cluster.sync.DNSMASQ_CONFIG_DIR', self.dnsmasq_dir),
            ('app_gateway.caddy_config_export.CADDY_EXPORT_DIR', self.export_dir),
            ('app_gateway.caddy_config_export.CERTIFICATE_EXPORT_DIR', self.certificate_export_dir),
        ):
            patcher = patch(target, value)
            patcher.start()
            self.addCleanup(patcher.stop)

        DNSSettings.objects.get_or_create(name='dns_settings')
        ClusterSettings.objects.update_or_create(name='cluster_settings', defaults={'enabled': True})
        self.worker = Worker.objects.create(name='node-a', hostname='node-a.example.test')
        self.headers = {'HTTP_AUTHORIZATION': f'Bearer {self.worker.token}', 'HTTP_X_WORKER_VERSION': '12'}

    def write_exported_certificate(self, hostname):
        host_dir = os.path.join(self.certificate_export_dir, hostname)
        os.makedirs(host_dir, exist_ok=True)
        with open(os.path.join(host_dir, 'certificate.crt'), 'w', encoding='utf-8') as certificate_file:
            certificate_file.write(FAKE_CERTIFICATE)
        with open(os.path.join(host_dir, 'certificate.key'), 'w', encoding='utf-8') as key_file:
            key_file.write(FAKE_PRIVATE_KEY)


@override_settings(CLUSTER_WORKER_MINIMUM_VERSION=12, WIREGUARD_STATUS_CACHE_ENABLED=True)
class ClusterApiTests(ClusterTestMixin, TestCase):
    def test_legacy_status_endpoint_stops_old_workers_without_token(self):
        response = self.client.get('/api/cluster/status/')
        self.assertEqual(response.status_code, 403)
        self.assertEqual(response.json()['message'], 'update_required')
        self.assertEqual(response.json()['minimum_worker_version'], 12)

    def test_manifest_requires_token(self):
        self.assertEqual(self.client.get('/api/cluster/v2/manifest/').status_code, 403)
        response = self.client.get('/api/cluster/v2/manifest/', HTTP_AUTHORIZATION='Bearer not-a-uuid')
        self.assertEqual(response.status_code, 403)

    def test_worker_is_refused_with_reason(self):
        scenarios = (
            ({'HTTP_X_WORKER_VERSION': '11'}, {}, 'update_required'),
            ({}, {'enabled': False}, 'worker_disabled'),
            ({}, {'ip_lock': True, 'ip_address': '203.0.113.10'}, 'ip_lock'),
        )
        for header_override, worker_fields, expected_error in scenarios:
            with self.subTest(expected_error=expected_error):
                Worker.objects.filter(pk=self.worker.pk).update(**{'enabled': True, 'ip_lock': False, **worker_fields})
                response = self.client.get('/api/cluster/v2/manifest/', **{**self.headers, **header_override})
                self.assertEqual(response.status_code, 400)
                self.assertEqual(response.json()['message'], expected_error)
                self.worker.refresh_from_db()
                self.assertEqual(self.worker.error_status, expected_error)

    def test_disabled_cluster_refuses_workers(self):
        ClusterSettings.objects.filter(name='cluster_settings').update(enabled=False)
        response = self.client.get('/api/cluster/v2/manifest/', **self.headers)
        self.assertEqual(response.status_code, 400)
        self.assertEqual(response.json()['message'], 'cluster_disabled')

    def test_manifest_hashes_match_sections(self):
        response = self.client.get('/api/cluster/v2/manifest/', **self.headers)
        self.assertEqual(response.status_code, 200)
        manifest = response.json()['sections']
        self.assertEqual(list(manifest), list(sync.SECTION_NAMES))
        for section_name, section_hash in manifest.items():
            with self.subTest(section=section_name):
                section_response = self.client.get(f'/api/cluster/v2/section/{section_name}/', **self.headers)
                self.assertEqual(section_response.status_code, 200)
                self.assertEqual(section_response.json()['hash'], section_hash)
        self.assertEqual(self.client.get('/api/cluster/v2/section/unknown/', **self.headers).status_code, 404)

    def test_report_stores_worker_status(self):
        report = {
            'sections': {
                'dns': {'hash': 'abc', 'status': 'error', 'message': 'dnsmasq failed'},
                'unknown': {'hash': 'abc', 'status': 'ok'},
                'settings': {'hash': 'def', 'status': 'invalid'},
            },
            'services': {'dnsmasq': 'running'},
            'certificates': {'app.example.test': {'status': 'trusted'}},
            'wireguard_status': {'wg0': {}},
        }
        response = self.client.post(
            '/api/cluster/v2/report/', data=json.dumps(report), content_type='application/json', **self.headers
        )
        self.assertEqual(response.status_code, 200)
        worker_status = WorkerStatus.objects.get(worker=self.worker)
        self.assertEqual(list(worker_status.section_status), ['dns'])
        self.assertEqual(worker_status.section_status['dns']['message'], 'dnsmasq failed')
        self.assertEqual(worker_status.services_status, {'dnsmasq': 'running'})
        self.assertEqual(worker_status.certificate_status, report['certificates'])
        self.assertEqual(worker_status.wireguard_status, {'wg0': {}})
        self.assertIsNotNone(worker_status.certificate_status_updated)
        self.assertIsNotNone(worker_status.wireguard_status_updated)

    def test_report_stores_gateway_sessions(self):
        sessions = [
            {'id': 'a' * 64, 'username': 'alice', 'factors': ['password'], 'online': True, 'session_id': 'secret'},
            {'id': 'invalid', 'username': 'mallory'},
        ]
        response = self.client.post(
            '/api/cluster/v2/report/', data=json.dumps({'gateway_sessions': sessions}), content_type='application/json',
            **self.headers
        )
        self.assertEqual(response.status_code, 200)
        worker_status = WorkerStatus.objects.get(worker=self.worker)
        self.assertEqual([session['id'] for session in worker_status.gateway_sessions], ['a' * 64])
        self.assertNotIn('session_id', worker_status.gateway_sessions[0])
        self.assertIsNotNone(worker_status.gateway_sessions_updated)

        # A report without sessions (older worker or no change) keeps the last ones
        self.client.post('/api/cluster/v2/report/', data=json.dumps({'services': {}}), content_type='application/json', **self.headers)
        self.assertEqual(len(WorkerStatus.objects.get(worker=self.worker).gateway_sessions), 1)


class ClusterSyncTests(ClusterTestMixin, TestCase):
    def report_sections(self, manifest, overrides=None):
        section_status = {name: {'hash': section_hash, 'status': 'ok'} for name, section_hash in manifest.items()}
        section_status.update(overrides or {})
        WorkerStatus.objects.update_or_create(worker=self.worker, defaults={'section_status': section_status})
        self.worker.refresh_from_db()

    def test_sync_state(self):
        manifest = sync.build_manifest(self.worker)
        self.assertEqual(sync.get_worker_sync_state(self.worker, manifest)['state'], 'pending')

        self.report_sections(manifest)
        self.assertEqual(sync.get_worker_sync_state(self.worker, manifest)['state'], 'synced')

        self.report_sections(manifest, {'dns': {'hash': manifest['dns'], 'status': 'error', 'message': 'failed'}})
        sync_state = sync.get_worker_sync_state(self.worker, manifest)
        self.assertEqual(sync_state['state'], 'error')
        self.assertEqual(sync_state['sections']['dns']['message'], 'failed')

        # An error reported for older content means the node still has to try the new one
        self.report_sections(manifest, {'dns': {'hash': 'old', 'status': 'error', 'message': 'failed'}})
        self.assertEqual(sync.get_worker_sync_state(self.worker, manifest)['state'], 'pending')

    def test_wireguard_section_follows_config_files(self):
        first_hash = sync.build_section('wireguard', self.worker).hash
        self.assertEqual(sync.build_section('wireguard', self.worker).hash, first_hash)
        with open(os.path.join(self.wireguard_dir, 'wg1.conf'), 'w', encoding='utf-8') as config_file:
            config_file.write('[Interface]\nListenPort = 51821\n')
        section = sync.build_section('wireguard', self.worker)
        self.assertNotEqual(section.hash, first_hash)
        self.assertEqual(sorted(section.files), ['wg0.conf', 'wg1.conf'])

    def test_dns_section_uses_node_configuration(self):
        section = sync.build_section('dns', self.worker)
        main_config = section.files[sync.DNSMASQ_MAIN_CONFIG]
        self.assertIn('bind-dynamic', main_config)
        self.assertIn('interface=wg*', main_config)
        self.assertNotIn('listen-address=0.0.0.0', main_config)

    def test_firewall_section_is_stable_and_node_specific(self):
        self.assertEqual(sync.build_section('firewall', self.worker).hash, sync.build_section('firewall', self.worker).hash)
        node_script = generate_firewall_script(cluster_node=True)
        primary_script = generate_firewall_script()
        self.assertNotIn('DNS_IP', node_script)
        self.assertNotIn('--dport 8000', node_script)
        self.assertNotIn('generated by', node_script)
        self.assertIn('DNS_IP', primary_script)


class ClusterGatewaySyncTests(ClusterTestMixin, TestCase):
    def setUp(self):
        super().setUp()
        self.credential = DnsChallengeCredential.objects.create(
            display_name='Cloudflare', provider='cloudflare', credentials={'api_token': 'x' * 40}
        )
        self.node_app = Application.objects.create(
            display_name='Node App', upstream='http://10.0.0.20:8080', serve_on_primary=False
        )
        self.node_app.workers.add(self.worker)
        ApplicationHost.objects.create(
            application=self.node_app, hostname='node.example.test', certificate_type='dns_challenge',
            dns_credential=self.credential,
        )

    def gateway_files(self):
        return {
            filename: json.loads(content)
            for filename, content in sync.build_section('gateway', self.worker).files.items()
        }

    def test_primary_manages_certificates_of_worker_only_applications(self):
        export_caddy_config(self.export_dir)
        with open(os.path.join(self.export_dir, 'applications.json'), encoding='utf-8') as applications_file:
            primary_applications = json.load(applications_file)
        with open(os.path.join(self.export_dir, 'tls.json'), encoding='utf-8') as tls_file:
            primary_tls = json.load(tls_file)
        self.assertNotIn('node-app', [entry['id'] for entry in primary_applications['entries']])
        host_tls = primary_tls['hosts']['node.example.test']
        self.assertTrue(host_tls['certificate_only'])
        self.assertTrue(host_tls['export_certificate'])
        self.assertEqual(host_tls['dns_credential'], self.credential.name)

    def test_workers_only_publish_exported_configuration(self):
        self.assertEqual(self.gateway_files()['applications.json'], {'entries': []})

        export_caddy_config(self.export_dir)
        self.assertEqual([entry['id'] for entry in self.gateway_files()['applications.json']['entries']], ['node-app'])

        self.node_app.upstream = 'http://10.0.0.21:8080'
        self.node_app.save()
        self.assertTrue(caddy_config_export.has_pending_export(self.export_dir))
        self.assertEqual(self.gateway_files()['applications.json']['entries'][0]['upstream'], 'http://10.0.0.20:8080')

        export_caddy_config(self.export_dir)
        self.assertFalse(caddy_config_export.has_pending_export(self.export_dir))
        self.assertEqual(self.gateway_files()['applications.json']['entries'][0]['upstream'], 'http://10.0.0.21:8080')

    def test_worker_receives_exported_certificate_without_dns_credentials(self):
        export_caddy_config(self.export_dir)
        worker_tls = self.gateway_files()['tls.json']
        self.assertEqual(worker_tls['dns_credentials'], {})
        self.assertEqual(worker_tls['hosts']['node.example.test']['certificate_file'], '')
        self.assertEqual(sync.build_section('certificates', self.worker).files, {})

        # A renewed certificate reaches the worker without a new export
        self.write_exported_certificate('node.example.test')
        certificate_name = certificate_file_name(FAKE_CERTIFICATE)
        self.assertEqual(self.gateway_files()['tls.json']['hosts']['node.example.test']['certificate_file'], certificate_name)
        self.assertEqual(sync.build_section('certificates', self.worker).files, {
            f'{certificate_name}.crt': FAKE_CERTIFICATE,
            f'{certificate_name}.key': FAKE_PRIVATE_KEY,
        })

    def test_new_worker_is_pending_until_exported(self):
        export_caddy_config(self.export_dir)
        self.assertFalse(caddy_config_export.has_pending_export(self.export_dir))
        Worker.objects.create(name='node-b')
        self.assertTrue(caddy_config_export.has_pending_export(self.export_dir))


class ClusterTrafficAggregationTests(TestCase):
    def test_peer_traffic_is_summed_across_servers(self):
        worker = Worker.objects.create(name='node-a')
        WorkerStatus.objects.create(
            worker=worker, wireguard_status_updated=timezone.now(), wireguard_status={'wg0': {
                'PEER': {'transfer': {'tx': 5000, 'rx': 500}, 'latest-handshakes': '2000', 'endpoints': 'node:1'},
                'NODE_ONLY': {'transfer': {'tx': 7, 'rx': 3}, 'latest-handshakes': '5'},
            }},
        )
        WireguardStatusCache.objects.create(cache_type='master', processing_time_ms=0, data={'wg0': {
            'PEER': {'transfer': {'tx': 100, 'rx': 10}, 'latest-handshakes': '1000', 'endpoints': 'primary:1'},
        }})

        func_concatenate_cluster_wireguard_status_cache()

        combined = WireguardStatusCache.objects.filter(cache_type='cluster').latest('created').data['wg0']
        self.assertEqual(combined['PEER']['transfer'], {'tx': 5100, 'rx': 510})
        self.assertEqual(combined['PEER']['endpoints'], 'node:1')
        self.assertEqual(combined['PEER']['source_name'], 'worker_node-a')
        self.assertEqual(combined['NODE_ONLY']['transfer'], {'tx': 7, 'rx': 3})


def create_instance(instance_id, worker=None):
    return WireGuardInstance.objects.create(
        instance_id=instance_id, private_key=f'private-{instance_id}', public_key=f'public-{instance_id}',
        hostname='primary.example.test', listen_port=51820 + instance_id, address=f'10.188.{instance_id}.1',
        worker=worker,
    )


@override_settings(WIREGUARD_STATUS_CACHE_ENABLED=True)
class DistributedModeTests(ClusterTestMixin, TestCase):
    """wg0 runs on the primary server, wg1 on node-a and node-b runs no instance."""

    def setUp(self):
        super().setUp()
        self.cluster_wireguard_dir = os.path.join(self.wireguard_dir, 'cluster')
        for target, value in (
            ('cluster.sync.CLUSTER_WIREGUARD_CONFIG_DIR', self.cluster_wireguard_dir),
            ('wireguard_tools.functions.WIREGUARD_CONFIG_DIR', self.wireguard_dir),
            ('wireguard_tools.functions.CLUSTER_WIREGUARD_CONFIG_DIR', self.cluster_wireguard_dir),
            ('wireguard_tools.views.WIREGUARD_CONFIG_DIR', self.wireguard_dir),
            ('wireguard_tools.views.CLUSTER_WIREGUARD_CONFIG_DIR', self.cluster_wireguard_dir),
        ):
            patcher = patch(target, value)
            patcher.start()
            self.addCleanup(patcher.stop)

        self.worker_b = Worker.objects.create(name='node-b', hostname='node-b.example.test')
        self.primary_instance = create_instance(0)
        self.worker_instance = create_instance(1, worker=self.worker)
        ClusterSettings.objects.filter(name='cluster_settings').update(cluster_mode='distributed')

    def set_mode(self, enabled=True, cluster_mode='distributed'):
        ClusterSettings.objects.filter(name='cluster_settings').update(enabled=enabled, cluster_mode=cluster_mode)

    def create_peer(self, instance):
        peer = Peer.objects.create(
            name=f'peer-wg{instance.instance_id}', public_key=f'peer-public-{instance.instance_id}',
            pre_shared_key='', private_key=f'peer-private-{instance.instance_id}', wireguard_instance=instance,
        )
        PeerAllowedIP.objects.create(
            peer=peer, priority=0, allowed_ip=f'10.188.{instance.instance_id}.10', netmask=32, config_file='server'
        )
        return peer

    def test_hosting_worker_only_in_distributed_mode(self):
        self.assertTrue(ClusterSettings.is_distributed())
        self.assertEqual(self.worker_instance.hosting_worker, self.worker)
        self.assertIsNone(self.primary_instance.hosting_worker)

        self.set_mode(cluster_mode='mirror')
        self.assertIsNone(WireGuardInstance.objects.get(instance_id=1).hosting_worker)
        self.set_mode(enabled=False)
        self.assertFalse(ClusterSettings.is_distributed())
        self.assertIsNone(WireGuardInstance.objects.get(instance_id=1).hosting_worker)

    def test_export_places_configs_by_server(self):
        FirewallSettings.objects.update_or_create(name='global', defaults={'instance_to_execute_firewall': self.worker_instance})
        export_wireguard_configuration()
        self.assertEqual(sorted(os.listdir(self.cluster_wireguard_dir)), ['wg1.conf'])
        self.assertIn('wg0.conf', os.listdir(self.wireguard_dir))
        self.assertNotIn('wg1.conf', os.listdir(self.wireguard_dir))
        # The firewall script must run from an instance of the primary server
        self.assertEqual(FirewallSettings.objects.get(name='global').instance_to_execute_firewall, self.primary_instance)
        with open(os.path.join(self.wireguard_dir, 'wg0.conf'), encoding='utf-8') as config_file:
            self.assertIn('PostUp = /etc/wireguard/wg-firewall.sh', config_file.read())

        # Moving a single instance back to the primary server removes it from the cluster directory
        WireGuardInstance.objects.filter(instance_id=1).update(worker=None)
        export_wireguard_configuration(WireGuardInstance.objects.get(instance_id=1))
        self.assertIn('wg1.conf', os.listdir(self.wireguard_dir))
        self.assertEqual(os.listdir(self.cluster_wireguard_dir), [])

    def test_wireguard_section_only_has_worker_instances(self):
        export_wireguard_configuration()
        self.assertEqual(sorted(sync.build_section('wireguard', self.worker).files), ['wg1.conf'])
        self.assertEqual(sync.build_section('wireguard', self.worker_b).files, {})

        self.set_mode(cluster_mode='mirror')
        export_wireguard_configuration()
        self.assertEqual(sorted(sync.build_section('wireguard', self.worker_b).files), ['wg0.conf', 'wg1.conf'])

    def test_port_forwards_only_on_instance_server(self):
        RedirectRule.objects.create(port=8081, wireguard_instance=self.worker_instance, ip_address='10.188.1.10')
        RedirectRule.objects.create(port=8082, wireguard_instance=self.primary_instance, ip_address='10.188.0.10')
        worker_script = generate_firewall_script(cluster_node=True, worker=self.worker)
        other_worker_script = generate_firewall_script(cluster_node=True, worker=self.worker_b)
        primary_script = generate_firewall_script()

        self.assertIn('--dport 8081', worker_script)
        self.assertNotIn('--dport 8082', worker_script)
        self.assertNotIn('--dport 808', other_worker_script)
        self.assertIn('--dport 8082', primary_script)
        self.assertNotIn('--dport 8081', primary_script)

        self.set_mode(cluster_mode='mirror')
        self.assertIn('--dport 8082', generate_firewall_script(cluster_node=True, worker=self.worker_b))

    def test_activation_blocked_by_instance_interface_rules(self):
        self.set_mode(cluster_mode='mirror')
        FirewallRule.objects.create(description='wg0 to internet', in_interface='wg0', out_interface='eth0')
        cluster_settings = ClusterSettings.objects.get(name='cluster_settings')
        data = {'enabled': True, 'primary_enable_wireguard': True, 'cluster_mode': 'distributed', 'worker_display': 'name'}

        form = ClusterSettingsForm(data=data, instance=cluster_settings)
        self.assertFalse(form.is_valid())
        self.assertIn('wg0 to internet', str(form.non_field_errors()))

        FirewallRule.objects.update(in_interface='wg+')
        self.assertTrue(ClusterSettingsForm(data=data, instance=cluster_settings).is_valid())

    def test_firewall_rule_form_rejects_instance_interface(self):
        def rule_form(in_interface):
            return FirewallRuleForm(data={
                'firewall_chain': 'forward', 'in_interface': in_interface, 'out_interface': '', 'rule_action': 'accept',
                'source_netmask': 32, 'destination_netmask': 32, 'protocol': '', 'sort_order': 10,
            })

        form = rule_form('wg0')
        self.assertFalse(form.is_valid())
        self.assertIn('distributed cluster mode', str(form.non_field_errors()))
        self.assertTrue(rule_form('wg+').is_valid())

        self.set_mode(cluster_mode='mirror')
        self.assertTrue(rule_form('wg0').is_valid())

    def test_peer_config_uses_instance_server(self):
        worker_peer = self.create_peer(self.worker_instance)
        primary_peer = self.create_peer(self.primary_instance)

        self.assertIn('Endpoint = node-a.example.test:51821', generate_peer_config(worker_peer.uuid))
        # A server picked for another worker is ignored: the instance only runs on node-a
        self.assertIn(
            'Endpoint = node-a.example.test:51821',
            generate_peer_config(worker_peer.uuid, server_address='node-b.example.test:51821'),
        )
        self.assertIn('Endpoint = primary.example.test:51820', generate_peer_config(primary_peer.uuid))

        self.assertEqual(get_config_servers(self.worker_instance), [{'name': 'node-a.example.test', 'uuid': str(self.worker.uuid)}])
        self.assertEqual([server['uuid'] for server in get_config_servers(self.primary_instance)], [''])

        self.set_mode(cluster_mode='mirror')
        self.assertEqual(len(get_config_servers(self.worker_instance)), 3)

    def test_worker_with_instances_cannot_be_deleted(self):
        user = User.objects.create_user(username='cluster-admin', password='unused-test-password')
        UserAcl.objects.create(user=user, user_level=50)
        self.client.force_login(user)

        response = self.client.get(f'/cluster/worker/manage/?uuid={self.worker.uuid}&action=delete&confirmation=delete')
        self.assertRedirects(response, f'/cluster/worker/view/?uuid={self.worker.uuid}', fetch_redirect_response=False)
        self.assertTrue(Worker.objects.filter(pk=self.worker.pk).exists())

        self.client.get(f'/cluster/worker/manage/?uuid={self.worker_b.uuid}&action=delete&confirmation=delete')
        self.assertFalse(Worker.objects.filter(pk=self.worker_b.pk).exists())


class AgentGatewaySessionsTests(TestCase):
    """Sessions of the node auth-gateway are reported when they change, and revocations reach its config."""

    @classmethod
    def setUpClass(cls):
        super().setUpClass()
        cls.cluster_worker = load_cluster_worker()

    def setUp(self):
        temp_dir = tempfile.TemporaryDirectory()
        self.addCleanup(temp_dir.cleanup)
        self.gateway_dir = temp_dir.name
        self.sessions_file = os.path.join(self.gateway_dir, 'state', 'sessions.json')
        os.makedirs(os.path.dirname(self.sessions_file))
        for name, value in (
            ('GATEWAY_DIR', self.gateway_dir),
            ('GATEWAY_SESSIONS_FILE', self.sessions_file),
            ('gateway_enabled', lambda: True),
            ('wireguard_status', lambda: {}),
        ):
            patcher = patch.object(self.cluster_worker, name, value)
            patcher.start()
            self.addCleanup(patcher.stop)
        for name in ('services_status', 'certificates_status'):
            patcher = patch.object(self.cluster_worker.ClusterNodeAgent, name, staticmethod(lambda: {}))
            patcher.start()
            self.addCleanup(patcher.stop)
        self.agent = self.cluster_worker.ClusterNodeAgent()
        self.reports = []
        self.status_code = 200
        self.agent.request = self.record_report

    def record_report(self, method, path, json=None):
        self.reports.append(json)
        return type('Response', (), {'status_code': self.status_code})()

    def publish(self, sessions):
        with open(self.sessions_file, 'w', encoding='utf-8') as sessions_file:
            sessions_file.write(json.dumps({'sessions': sessions}))

    def test_sessions_are_only_reported_when_they_change(self):
        self.publish([{'id': 'a' * 64}])
        self.agent.send_stats()
        self.agent.send_stats()
        self.publish([])
        self.agent.send_stats()
        self.assertEqual([report.get('gateway_sessions') for report in self.reports], [[{'id': 'a' * 64}], None, []])

    def test_sessions_are_reported_again_when_the_primary_did_not_accept_them(self):
        self.publish([{'id': 'a' * 64}])
        self.status_code = 500
        self.agent.send_stats()
        self.status_code = 200
        self.agent.send_stats()
        self.agent.send_stats()
        self.assertEqual(['gateway_sessions' in report for report in self.reports], [True, True, False])

    def test_no_sessions_file_reports_nothing(self):
        self.agent.send_stats()
        self.assertNotIn('gateway_sessions', self.reports[0])

    def test_revoked_sessions_are_written_when_sent(self):
        files = {name: '{}' for name in self.cluster_worker.GATEWAY_FILES}
        self.agent.apply_gateway({'files': files})
        self.assertFalse(os.path.exists(os.path.join(self.gateway_dir, 'revoked_sessions.json')))
        self.agent.apply_gateway({'files': dict(files, **{'revoked_sessions.json': '{"sessions": []}'})})
        with open(os.path.join(self.gateway_dir, 'revoked_sessions.json'), encoding='utf-8') as revoked_file:
            self.assertEqual(revoked_file.read(), '{"sessions": []}')
