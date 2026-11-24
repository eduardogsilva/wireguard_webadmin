import json
import os
import subprocess
import tempfile
from decimal import Decimal
from unittest.mock import patch

from django.conf import settings
from django.contrib.auth.models import User
from django.db.models import ProtectedError
from django.test import TestCase, override_settings

from api_v2.models import ApiKey
from cluster import sync
from cluster.models import ClusterSettings, Worker, WorkerStatus
from cluster.tests import ClusterTestMixin, create_instance
from speed_profiles.forms import SpeedProfileForm
from speed_profiles.models import SpeedProfile
from user_manager.models import UserAcl
from wireguard.models import Peer, PeerAllowedIP, WireGuardInstance
from wireguard_peer.functions import func_create_new_peer
from wireguard_tools import functions
from wireguard_tools.speed_limits import apply_speed_limits, build_tc_commands, parse_speed_limits
from wireguard_tools.tests import FakeNetwork, load_cluster_worker
from wireguard_tools.views import export_wireguard_configuration


def create_peer(instance, number, speed_profile=None, networks=(), endpoint=''):
    peer = Peer.objects.create(
        name=f'peer-{number}', public_key=f'peer-public-{number}', pre_shared_key='', private_key=f'private-{number}',
        wireguard_instance=instance, speed_profile=speed_profile, endpoint=endpoint,
    )
    PeerAllowedIP.objects.create(
        peer=peer, priority=0, allowed_ip=f'10.188.{instance.instance_id}.{number}', netmask=32, config_file='server'
    )
    for priority, network in enumerate(networks, start=1):
        address, netmask = network.split('/')
        PeerAllowedIP.objects.create(
            peer=peer, priority=priority, allowed_ip=address, netmask=int(netmask), config_file='server'
        )
    return peer


class SpeedProfileFormTests(TestCase):
    def form(self, **data):
        return SpeedProfileForm(data={'name': 'Basic', **data})

    def test_accepts_optional_and_decimal_limits(self):
        self.assertTrue(self.form(download_limit='0.5').is_valid())
        self.assertTrue(self.form(upload_limit='10').is_valid())
        form = self.form(download_limit='10', download_burst='5', upload_limit='2.5', upload_burst='0.25')
        self.assertTrue(form.is_valid(), form.errors)

    def test_refuses_zero_and_negative_values(self):
        for field_name in ('download_limit', 'upload_limit'):
            for value in ('0', '-1'):
                form = self.form(**{field_name: value})
                self.assertFalse(form.is_valid())
                self.assertIn(field_name, form.errors)
        form = self.form(download_limit='10', download_burst='0')
        self.assertIn('download_burst', form.errors)

    def test_refuses_repeated_name(self):
        SpeedProfile.objects.create(name='Basic', download_limit=10)
        form = self.form(download_limit='20')
        self.assertFalse(form.is_valid())
        self.assertIn('name', form.errors)

    def test_refuses_profile_without_limits(self):
        form = self.form()
        self.assertFalse(form.is_valid())
        self.assertIn('__all__', form.errors)

    def test_refuses_burst_without_the_limit_of_its_direction(self):
        form = self.form(download_limit='10', upload_burst='5')
        self.assertFalse(form.is_valid())
        self.assertIn('upload_burst', form.errors)


class SpeedProfileViewMixin:
    def setUp(self):
        super().setUp()
        user = User.objects.create_user(username='admin', password='unused')
        UserAcl.objects.create(user=user, user_level=50)
        self.client.force_login(user)
        self.instance = create_instance(0)
        self.other_instance = create_instance(1)
        self.profile = SpeedProfile.objects.create(name='Basic', download_limit=10, upload_limit=5)


class SpeedProfileDeleteTests(SpeedProfileViewMixin, TestCase):
    def test_profile_in_use_is_protected(self):
        create_peer(self.instance, 10, self.profile)
        with self.assertRaises(ProtectedError):
            self.profile.delete()

    def test_delete_page_lists_peers_and_instances(self):
        create_peer(self.instance, 10, self.profile)
        WireGuardInstance.objects.filter(pk=self.other_instance.pk).update(default_speed_profile=self.profile)
        response = self.client.get('/speed_profiles/delete/', {'uuid': str(self.profile.uuid)})
        self.assertContains(response, 'peer-10')
        self.assertContains(response, 'wg1')
        self.assertContains(response, 'unlink_and_delete')

    @patch('speed_profiles.views._auto_apply', return_value=False)
    def test_unlink_and_delete(self, auto_apply):
        peer = create_peer(self.instance, 10, self.profile)
        WireGuardInstance.objects.filter(pk=self.other_instance.pk).update(default_speed_profile=self.profile)

        # Without the unlink action nothing is deleted
        self.client.post(f'/speed_profiles/delete/?uuid={self.profile.uuid}', {'action': 'delete'})
        self.assertTrue(SpeedProfile.objects.filter(pk=self.profile.pk).exists())

        response = self.client.post(f'/speed_profiles/delete/?uuid={self.profile.uuid}', {'action': 'unlink_and_delete'})
        self.assertRedirects(response, '/speed_profiles/', fetch_redirect_response=False)
        self.assertFalse(SpeedProfile.objects.filter(pk=self.profile.pk).exists())
        peer.refresh_from_db()
        self.assertIsNone(peer.speed_profile)
        self.other_instance.refresh_from_db()
        self.assertIsNone(self.other_instance.default_speed_profile)
        # The instance whose peer lost the limit is applied again (pending without auto apply)
        auto_apply.assert_called_once()
        self.instance.refresh_from_db()
        self.assertTrue(self.instance.pending_changes)


class SpeedProfileEditTests(SpeedProfileViewMixin, TestCase):
    def edit(self):
        return self.client.post(
            f'/speed_profiles/manage/?uuid={self.profile.uuid}', {'name': 'Basic', 'download_limit': '20', 'upload_limit': '5'}
        )

    @patch('speed_profiles.views._auto_apply', return_value=True)
    def test_edit_applies_the_instances_using_the_profile(self, auto_apply):
        create_peer(self.instance, 10, self.profile)
        create_peer(self.instance, 11, self.profile)
        create_peer(self.other_instance, 12)
        self.edit()
        self.assertEqual([call.args[1] for call in auto_apply.call_args_list], [self.instance])

    @patch('speed_profiles.views._auto_apply', return_value=False)
    def test_edit_marks_instances_pending_without_auto_apply(self, auto_apply):
        WireGuardInstance.objects.update(pending_changes=False)
        create_peer(self.instance, 10, self.profile)
        self.edit()
        self.instance.refresh_from_db()
        self.other_instance.refresh_from_db()
        self.assertTrue(self.instance.pending_changes)
        self.assertFalse(self.other_instance.pending_changes)


class DefaultSpeedProfileTests(TestCase):
    def setUp(self):
        self.default_profile = SpeedProfile.objects.create(name='Default', download_limit=10)
        self.other_profile = SpeedProfile.objects.create(name='Other', upload_limit=5)
        self.instance = create_instance(0)
        WireGuardInstance.objects.filter(pk=self.instance.pk).update(default_speed_profile=self.default_profile)
        self.instance.refresh_from_db()
        self.api_key = ApiKey.objects.create(name='key', enabled=True)

    def test_new_peer_gets_the_default_profile(self):
        peer, message = func_create_new_peer(self.instance)
        self.assertEqual(peer.speed_profile, self.default_profile)

    def test_override_replaces_the_default_profile(self):
        peer, message = func_create_new_peer(self.instance, {'speed_profile': None})
        self.assertIsNone(peer.speed_profile)

    def api_create(self, **payload):
        return self.client.post(
            '/api/v2/manage_peer/', data=json.dumps({'instance': 'wg0', 'skip_reload': True, **payload}),
            content_type='application/json', HTTP_TOKEN=str(self.api_key.token),
        )

    def test_api_uses_the_default_profile_when_none_is_informed(self):
        response = self.api_create(name='from-api')
        self.assertEqual(response.status_code, 201, response.content)
        self.assertEqual(Peer.objects.get(uuid=response.json()['peer_uuid']).speed_profile, self.default_profile)

    def test_api_informed_profile_replaces_the_default(self):
        response = self.api_create(name='other', speed_profile_uuid=str(self.other_profile.uuid))
        self.assertEqual(Peer.objects.get(uuid=response.json()['peer_uuid']).speed_profile, self.other_profile)
        response = self.api_create(name='unlimited', speed_profile_uuid='')
        self.assertIsNone(Peer.objects.get(uuid=response.json()['peer_uuid']).speed_profile)


class ExportedConfigMixin:
    """Exports the WireGuard configuration of the instances to a temporary directory."""

    def setUp(self):
        super().setUp()
        temp_dir = tempfile.TemporaryDirectory()
        self.addCleanup(temp_dir.cleanup)
        self.wireguard_dir = temp_dir.name
        cluster_dir = os.path.join(self.wireguard_dir, 'cluster')
        # Every module that resolves the configuration directory must point to the temporary one
        for target, value in (
            ('wireguard_tools.functions.WIREGUARD_CONFIG_DIR', self.wireguard_dir),
            ('wireguard_tools.functions.CLUSTER_WIREGUARD_CONFIG_DIR', cluster_dir),
            ('wireguard_tools.views.WIREGUARD_CONFIG_DIR', self.wireguard_dir),
            ('wireguard_tools.views.CLUSTER_WIREGUARD_CONFIG_DIR', cluster_dir),
        ):
            patcher = patch(target, value)
            patcher.start()
            self.addCleanup(patcher.stop)

    def exported_limits(self, instance_id=0):
        export_wireguard_configuration()
        with open(os.path.join(self.wireguard_dir, f'wg{instance_id}.conf')) as config_file:
            return parse_speed_limits(config_file.read())


class SpeedLimitRuleTests(ExportedConfigMixin, TestCase):
    def setUp(self):
        super().setUp()
        self.instance = create_instance(0)

    def test_each_limited_peer_gets_its_own_rules_covering_all_its_networks(self):
        profile = SpeedProfile.objects.create(name='Basic', download_limit=10, upload_limit=Decimal('2.5'))
        create_peer(self.instance, 10, profile, networks=['192.168.50.0/24'])
        create_peer(self.instance, 11, profile)
        create_peer(self.instance, 12)

        limits = self.exported_limits()
        self.assertEqual(
            [sorted(str(network) for network in peer['networks']) for peer in limits],
            [['10.188.0.10/32', '192.168.50.0/24'], ['10.188.0.11/32']],
        )
        commands = build_tc_commands('wg0', limits)
        # One download class on the interface and one upload class on its ifb per peer
        self.assertEqual(len([command for command in commands if command.startswith('class add dev wg0 ')]), 2)
        self.assertEqual(len([command for command in commands if command.startswith('class add dev ifbwg0 ')]), 2)
        # Only the networks of limited peers are redirected to the ifb
        redirects = [command for command in commands if 'action mirred egress redirect dev ifbwg0' in command]
        self.assertEqual(len(redirects), 3)
        upload_filters = [command for command in commands if command.startswith('filter add dev ifbwg0 ')]
        self.assertEqual(len(upload_filters), 3)
        # Both networks of the first peer go to the same class, so the limit covers the peer as a whole
        self.assertEqual({command.split('flowid ')[1] for command in upload_filters[:2]}, {'1:1'})
        self.assertTrue(all('10.188.0.12' not in command for command in commands))

    def test_profile_with_one_direction_only_limits_that_direction(self):
        create_peer(self.instance, 10, SpeedProfile.objects.create(name='Down', download_limit=10))
        create_peer(self.instance, 11, SpeedProfile.objects.create(name='Up', upload_limit=5))
        commands = build_tc_commands('wg0', self.exported_limits())
        download_filters = [command for command in commands if 'match ip dst' in command]
        upload_filters = [command for command in commands if command.startswith('filter add dev ifbwg0 ')]
        self.assertEqual([command.split('ip dst ')[1].split()[0] for command in download_filters], ['10.188.0.10/32'])
        self.assertEqual([command.split('ip src ')[1].split()[0] for command in upload_filters], ['10.188.0.11/32'])

    def test_burst_is_used_when_informed(self):
        create_peer(self.instance, 10, SpeedProfile.objects.create(
            name='Burst', download_limit=10, download_burst=5, upload_limit=10, upload_burst=Decimal('0.5'),
        ))
        create_peer(self.instance, 11, SpeedProfile.objects.create(name='Auto', download_limit=10, upload_limit=8))
        commands = build_tc_commands('wg0', self.exported_limits())
        download_classes = [command for command in commands if command.startswith('class add dev wg0 ')]
        upload_classes = [command for command in commands if command.startswith('class add dev ifbwg0 ')]
        self.assertIn('burst 5000000b cburst 5000000b', download_classes[0])
        self.assertIn('burst 500000b cburst 500000b', upload_classes[0])
        # Without a burst, htb uses its automatic value
        self.assertNotIn('burst', download_classes[1])
        self.assertNotIn('burst', upload_classes[1])

    def test_peer_with_endpoint_gets_the_same_rules(self):
        profile = SpeedProfile.objects.create(name='Basic', download_limit=10, upload_limit=5)
        create_peer(self.instance, 10, profile, networks=['192.168.70.0/24'], endpoint='remote.example.test:51820')
        limits = self.exported_limits()
        self.assertEqual(len(limits), 1)
        self.assertEqual(limits[0]['download_kbit'], 10000)
        self.assertEqual(limits[0]['upload_kbit'], 5000)


class FakeTc:
    def __init__(self, fail=False, ifb=True):
        self.fail = fail
        self.ifb = ifb
        self.batches = []
        self.commands = []

    def run(self, command, *args, input=None, **kwargs):
        self.commands.append(command)
        if command[:2] == ['tc', '-batch']:
            self.batches.append(input.splitlines())
            if self.fail:
                return subprocess.CompletedProcess(command, 1, '', 'Error: Specified qdisc kind is unknown.')
        if command[:3] == ['ip', 'link', 'add'] and not self.ifb:
            return subprocess.CompletedProcess(command, 2, '', 'Error: Unknown device type.')
        return subprocess.CompletedProcess(command, 0, '', '')


class ApplySpeedLimitsTests(TestCase):
    def setUp(self):
        temp_dir = tempfile.TemporaryDirectory()
        self.addCleanup(temp_dir.cleanup)
        self.config_path = os.path.join(temp_dir.name, 'wg0.conf')

    def write_config(self, *peers):
        blocks = ['[Interface]\nListenPort = 51820\n']
        for address, limit in peers:
            blocks.append(f'[Peer]\nPublicKey = {address}\n# Speed limit: {limit}\nAllowedIPs = {address}/32\n')
        with open(self.config_path, 'w') as config_file:
            config_file.write('\n'.join(blocks))

    def test_limits_are_replaced_on_each_application(self):
        tc = FakeTc()
        self.write_config(('10.188.0.2', 'download_kbit=10000'), ('10.188.0.3', 'upload_kbit=5000'))
        self.assertEqual(apply_speed_limits('wg0', self.config_path, run=tc.run), [])
        self.assertTrue(any('10.188.0.3/32' in command for command in tc.batches[0]))

        # Changed limit and a peer that lost its profile
        self.write_config(('10.188.0.2', 'download_kbit=20000'))
        apply_speed_limits('wg0', self.config_path, run=tc.run)
        self.assertIn(['tc', 'qdisc', 'del', 'dev', 'wg0', 'root'], tc.commands)
        self.assertIn(['tc', 'qdisc', 'del', 'dev', 'wg0', 'ingress'], tc.commands)
        self.assertTrue(any('rate 20000kbit' in command for command in tc.batches[1]))
        self.assertFalse(any('10.188.0.3' in command for command in tc.batches[1]))

        # Without limited peers the previous limits and the ifb are only removed
        self.write_config()
        apply_speed_limits('wg0', self.config_path, run=tc.run)
        self.assertEqual(len(tc.batches), 2)
        self.assertEqual(tc.commands[-3:], [
            ['tc', 'qdisc', 'del', 'dev', 'wg0', 'root'], ['tc', 'qdisc', 'del', 'dev', 'wg0', 'ingress'],
            ['ip', 'link', 'delete', 'ifbwg0'],
        ])

    def test_upload_limits_create_the_ifb(self):
        tc = FakeTc()
        self.write_config(('10.188.0.2', 'upload_kbit=5000'))
        self.assertEqual(apply_speed_limits('wg0', self.config_path, run=tc.run), [])
        self.assertIn(['ip', 'link', 'add', 'ifbwg0', 'type', 'ifb'], tc.commands)
        self.assertIn(['ip', 'link', 'set', 'ifbwg0', 'up', 'txqueuelen', '1000'], tc.commands)
        self.assertIn('class add dev ifbwg0 parent 1: classid 1:1 htb rate 5000kbit ceil 5000kbit', tc.batches[0])

    def test_without_ifb_only_download_limits_are_applied(self):
        tc = FakeTc(ifb=False)
        self.write_config(('10.188.0.2', 'download_kbit=10000 upload_kbit=5000'))
        errors = apply_speed_limits('wg0', self.config_path, run=tc.run)
        self.assertEqual(len(errors), 1)
        self.assertIn('upload limits need the ifb kernel module', errors[0])
        self.assertTrue(any('rate 10000kbit' in command for command in tc.batches[0]))
        self.assertFalse(any('ifbwg0' in command for command in tc.batches[0]))

    def test_failure_is_returned_and_partial_limits_are_removed(self):
        tc = FakeTc(fail=True)
        self.write_config(('10.188.0.2', 'download_kbit=10000'))
        errors = apply_speed_limits('wg0', self.config_path, run=tc.run)
        self.assertEqual(errors, ['Error: Specified qdisc kind is unknown.'])
        self.assertEqual(tc.commands[-1], ['ip', 'link', 'delete', 'ifbwg0'])

    def test_failure_does_not_fail_the_reload(self):
        self.write_config(('10.188.0.2', 'download_kbit=10000'))
        network = FakeNetwork('wg0', ['10.188.0.2/32'], {'10.188.0.0/24': True})
        tc = FakeTc(fail=True)

        def run(command, *args, **kwargs):
            if command[0] == 'tc':
                return tc.run(command, *args, **kwargs)
            if command[:2] == ['wg-quick', 'strip']:
                return subprocess.CompletedProcess(command, 0, '[Interface]\n', '')
            return network.run(command)

        with patch('wireguard_tools.functions.subprocess.run', side_effect=run):
            success, message = functions.func_reload_wireguard_interface('wg0', os.path.dirname(self.config_path))
        self.assertTrue(success)
        self.assertIn(functions.SPEED_LIMIT_WARNING, message)
        self.assertIn('qdisc kind is unknown', message)

    def test_agent_ships_the_same_module(self):
        agent_copy = os.path.join(settings.BASE_DIR, 'containers', 'cluster_node', 'speed_limits.py')
        primary_copy = os.path.join(settings.BASE_DIR, 'wireguard_tools', 'speed_limits.py')
        with open(agent_copy) as agent_file, open(primary_copy) as primary_file:
            self.assertEqual(agent_file.read(), primary_file.read())


@override_settings(CLUSTER_WORKER_MINIMUM_VERSION=12, WIREGUARD_STATUS_CACHE_ENABLED=True)
class ClusterSpeedLimitTests(ClusterTestMixin, TestCase):
    def setUp(self):
        super().setUp()
        cluster_dir = os.path.join(self.wireguard_dir, 'cluster')
        for target, value in (
            ('cluster.sync.CLUSTER_WIREGUARD_CONFIG_DIR', cluster_dir),
            ('wireguard_tools.functions.WIREGUARD_CONFIG_DIR', self.wireguard_dir),
            ('wireguard_tools.functions.CLUSTER_WIREGUARD_CONFIG_DIR', cluster_dir),
            ('wireguard_tools.views.WIREGUARD_CONFIG_DIR', self.wireguard_dir),
            ('wireguard_tools.views.CLUSTER_WIREGUARD_CONFIG_DIR', cluster_dir),
        ):
            patcher = patch(target, value)
            patcher.start()
            self.addCleanup(patcher.stop)
        self.worker_b = Worker.objects.create(name='node-b', hostname='node-b.example.test')
        profile = SpeedProfile.objects.create(name='Basic', download_limit=10)
        self.primary_instance = create_instance(0)
        self.worker_instance = create_instance(1, worker=self.worker)
        create_peer(self.primary_instance, 10, profile)
        create_peer(self.worker_instance, 11, profile)

    def section_limits(self, worker):
        files = sync.build_section('wireguard', worker).files
        return {filename: parse_speed_limits(content) for filename, content in files.items()}

    def test_mirror_workers_receive_the_limits_of_every_instance(self):
        ClusterSettings.objects.filter(name='cluster_settings').update(cluster_mode='mirror')
        export_wireguard_configuration()
        limits = self.section_limits(self.worker_b)
        self.assertEqual(sorted(limits), ['wg0.conf', 'wg1.conf'])
        self.assertTrue(all(len(peers) == 1 for peers in limits.values()))

    def test_distributed_worker_only_receives_the_limits_of_its_instance(self):
        ClusterSettings.objects.filter(name='cluster_settings').update(cluster_mode='distributed')
        export_wireguard_configuration()
        limits = self.section_limits(self.worker)
        self.assertEqual(list(limits), ['wg1.conf'])
        self.assertEqual(str(limits['wg1.conf'][0]['networks'][0]), '10.188.1.11/32')
        self.assertEqual(self.section_limits(self.worker_b), {})

    def test_report_warning_is_stored_and_shown(self):
        ClusterSettings.objects.filter(name='cluster_settings').update(cluster_mode='mirror')
        export_wireguard_configuration()
        wireguard_hash = sync.build_manifest(self.worker)['wireguard']
        report = {'sections': {'wireguard': {
            'hash': wireguard_hash, 'status': 'ok', 'warning': 'wg0: speed limits not fully applied: no htb',
        }}}
        self.client.post('/api/cluster/v2/report/', data=json.dumps(report), content_type='application/json', **self.headers)
        self.assertEqual(
            WorkerStatus.objects.get(worker=self.worker).section_status['wireguard']['warning'],
            'wg0: speed limits not fully applied: no htb',
        )
        self.assertEqual(sync.get_worker_warnings(self.worker)['section_warnings'], ['wireguard'])

        user = User.objects.create_user(username='admin', password='unused')
        UserAcl.objects.create(user=user, user_level=50)
        self.client.force_login(user)
        response = self.client.get('/cluster/worker/view/', {'uuid': str(self.worker.uuid)})
        self.assertContains(response, 'Synchronized with warnings')
        self.assertContains(response, 'speed limits not fully applied: no htb')


class AgentSpeedLimitTests(TestCase):
    CONFIG = '[Interface]\nListenPort = 51820\n\n[Peer]\nPublicKey = a\n# Speed limit: download_kbit=1000\nAllowedIPs = 10.188.0.2/32\n'

    @classmethod
    def setUpClass(cls):
        super().setUpClass()
        cls.cluster_worker = load_cluster_worker()

    def setUp(self):
        temp_dir = tempfile.TemporaryDirectory()
        self.addCleanup(temp_dir.cleanup)
        for name, value in (('WIREGUARD_DIR', temp_dir.name), ('interface_is_up', lambda interface: False)):
            patcher = patch.object(self.cluster_worker, name, value)
            patcher.start()
            self.addCleanup(patcher.stop)
        self.agent = self.cluster_worker.ClusterNodeAgent()

    def test_speed_limit_failure_keeps_the_interface_and_is_reported(self):
        with patch.object(self.cluster_worker, 'run_command') as run_command, \
                patch.object(self.cluster_worker, 'apply_speed_limits', return_value=['no htb']) as apply_limits:
            self.agent.apply_wireguard({'files': {'wg0.conf': self.CONFIG}})
        run_command.assert_called_once_with(['wg-quick', 'up', 'wg0'])
        apply_limits.assert_called_once()
        self.assertEqual(self.agent.section_warnings['wireguard'], 'wg0: speed limits not fully applied: no htb')

        manifest = {'sections': {'wireguard': 'hash-1'}}
        section = {'hash': 'hash-1', 'files': {'wg0.conf': self.CONFIG}}
        responses = {'manifest/': manifest, 'section/wireguard/': section}
        reports = []

        def request(method, path, **kwargs):
            if method == 'POST':
                reports.append(kwargs['json'])
                return None
            return type('Response', (), {'status_code': 200, 'json': lambda self: responses[path], 'text': ''})()

        with patch.object(self.agent, 'request', side_effect=request), \
                patch.object(self.agent, 'response_json', side_effect=lambda response, path: responses[path]), \
                patch.object(self.cluster_worker, 'run_command'), \
                patch.object(self.cluster_worker, 'apply_speed_limits', return_value=['no htb']):
            self.agent.sync_configuration()
        self.assertEqual(reports[0]['sections']['wireguard']['status'], 'ok')
        self.assertEqual(reports[0]['sections']['wireguard']['warning'], 'wg0: speed limits not fully applied: no htb')


class ApiSpeedProfileTests(TestCase):
    def setUp(self):
        self.instance = create_instance(0)
        self.profile = SpeedProfile.objects.create(name='Basic', download_limit=10)
        self.peer = create_peer(self.instance, 10)
        self.api_key = ApiKey.objects.create(name='key', enabled=True)

    def post(self, path, method='post', **payload):
        return getattr(self.client, method)(
            path, data=json.dumps({'instance': 'wg0', **payload}), content_type='application/json',
            HTTP_TOKEN=str(self.api_key.token),
        )

    def update(self, value):
        return self.post('/api/v2/manage_peer/', method='put', peer_uuid=str(self.peer.uuid), skip_reload=True,
                         speed_profile_uuid=value)

    def test_manage_peer_sets_and_clears_the_profile(self):
        response = self.update(str(self.profile.uuid))
        self.assertEqual(response.status_code, 200, response.content)
        self.peer.refresh_from_db()
        self.assertEqual(self.peer.speed_profile, self.profile)

        self.update('')
        self.peer.refresh_from_db()
        self.assertIsNone(self.peer.speed_profile)

    def test_manage_peer_refuses_an_invalid_profile(self):
        for value in ('00000000-0000-0000-0000-000000000000', 'not-a-uuid'):
            response = self.update(value)
            self.assertEqual(response.status_code, 400)
            self.assertEqual(response.json()['error_message'], 'Invalid speed_profile_uuid.')

    def test_peer_detail_and_list_return_the_profile(self):
        Peer.objects.filter(pk=self.peer.pk).update(speed_profile=self.profile)
        detail = self.post('/api/v2/peer_detail/', peer_uuid=str(self.peer.uuid)).json()
        self.assertEqual(detail['peer']['speed_profile_uuid'], str(self.profile.uuid))
        peers = self.post('/api/v2/peer_list/').json()['peers']
        self.assertEqual(peers[0]['speed_profile_uuid'], str(self.profile.uuid))
