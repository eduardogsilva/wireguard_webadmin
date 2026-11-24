import importlib.util
import ipaddress
import os
import subprocess
import sys
import tempfile
from unittest.mock import patch

from django.conf import settings
from django.contrib.auth.models import User
from django.contrib.messages import get_messages
from django.test import TestCase

from user_manager.models import UserAcl
from wireguard.models import WireGuardInstance
from wireguard_tools import functions


def load_cluster_worker():
    agent_dir = os.path.join(settings.BASE_DIR, 'containers', 'cluster_node')
    spec = importlib.util.spec_from_file_location('cluster_worker_under_test', os.path.join(agent_dir, 'cluster_worker.py'))
    module = importlib.util.module_from_spec(spec)
    # The agent imports speed_limits from its own directory, as in the cluster node image
    sys.path.insert(0, agent_dir)
    try:
        spec.loader.exec_module(module)
    finally:
        sys.path.remove(agent_dir)
    return module


class FakeNetwork:
    """
    Minimal stand-in for the wg and ip commands used to synchronize routes. Keeps the routes of one interface and
    answers 'route show ... match' like iproute2: routes whose prefix contains the given network.
    """

    def __init__(self, interface, allowed_ips, routes):
        self.interface = interface
        self.allowed_ips = allowed_ips
        # {network: is_kernel_route}
        self.routes = {ipaddress.ip_network(route): kernel for route, kernel in routes.items()}
        self.commands = []

    def route_lines(self):
        return [
            f'{network} proto kernel scope link src x' if kernel else f'{network} scope link '
            for network, kernel in sorted(self.routes.items(), key=lambda item: str(item[0]))
        ]

    def run(self, command, *args, **kwargs):
        self.commands.append(command)
        stdout = ''
        if command[:2] == ['ip', 'link'] or command[0] == 'tc':
            # Devices and qdiscs of the speed limits are not part of the routes
            return subprocess.CompletedProcess(command, 0, '', '')
        if command[:2] == ['wg', 'show']:
            stdout = ''.join(f'peer{index}\t{value}\n' for index, value in enumerate(self.allowed_ips))
        elif command[0] == 'ip':
            arguments = [value for value in command[1:] if value not in ('-o', '-4')]
            action = arguments[1]
            if action == 'show' and 'match' in arguments:
                network = ipaddress.ip_network(arguments[-1])
                stdout = '\n'.join(
                    line for line in self.route_lines()
                    if network.subnet_of(ipaddress.ip_network(line.split()[0]))
                )
            elif action == 'show':
                stdout = '\n'.join(self.route_lines())
            elif action == 'replace':
                self.routes[ipaddress.ip_network(arguments[2])] = False
            elif action == 'delete':
                self.routes.pop(ipaddress.ip_network(arguments[2]), None)
        return subprocess.CompletedProcess(command, 0, stdout, '')

    def route_names(self):
        return sorted(str(network) for network in self.routes)


class RouteSyncCases:
    """Cases shared by the primary server and the cluster node agent implementations."""

    def sync(self, network):
        raise NotImplementedError

    def test_adds_route_of_new_allowed_network(self):
        network = FakeNetwork('wg0', ['10.188.0.2/32 192.168.60.0/24'], {'10.188.0.0/24': True})
        self.sync(network)
        self.assertEqual(network.route_names(), ['10.188.0.0/24', '192.168.60.0/24'])

    def test_does_not_add_route_already_covered(self):
        network = FakeNetwork(
            'wg0', ['10.188.0.2/32 192.168.15.128/25', '10.188.0.3/32 192.168.15.0/24'], {'10.188.0.0/24': True}
        )
        self.sync(network)
        # Peer addresses are covered by the instance route and the /25 by the /24 added first
        self.assertEqual(network.route_names(), ['10.188.0.0/24', '192.168.15.0/24'])
        replaced = [command[4] for command in network.commands if command[0] == 'ip' and 'replace' in command]
        self.assertEqual(replaced, ['192.168.15.0/24'])

    def test_removes_route_not_covered_by_allowed_ips(self):
        network = FakeNetwork(
            'wg0', ['10.188.0.2/32 192.168.15.0/24'],
            {'10.188.0.0/24': True, '192.168.15.0/24': False, '192.168.15.128/25': False, '192.168.99.0/24': False},
        )
        self.sync(network)
        # The kernel route and the route covered by an allowed network stay
        self.assertEqual(network.route_names(), ['10.188.0.0/24', '192.168.15.0/24', '192.168.15.128/25'])

    def test_keeps_kernel_route_without_peers(self):
        network = FakeNetwork('wg0', ['(none)'], {'10.188.0.0/24': True, '192.168.60.0/24': False})
        self.sync(network)
        self.assertEqual(network.route_names(), ['10.188.0.0/24'])

    def test_ignores_default_route(self):
        network = FakeNetwork('wg0', ['10.188.0.2/32 0.0.0.0/0'], {'10.188.0.0/24': True})
        self.sync(network)
        self.assertEqual(network.route_names(), ['10.188.0.0/24'])
        self.assertFalse([command for command in network.commands if 'replace' in command])


class PrimaryRouteSyncTests(RouteSyncCases, TestCase):
    def sync(self, network):
        with patch('wireguard_tools.functions.subprocess.run', side_effect=network.run):
            self.assertEqual(functions.sync_interface_routes(network.interface), [])

    def test_reload_syncs_routes_after_syncconf(self):
        network = FakeNetwork('wg0', ['10.188.0.2/32 192.168.60.0/24'], {'10.188.0.0/24': True})
        with patch('wireguard_tools.functions.os.path.exists', return_value=True), \
                patch('wireguard_tools.functions.os.remove'), \
                patch('builtins.open'), \
                patch('wireguard_tools.functions.subprocess.run', side_effect=network.run):
            success, message = functions.func_reload_wireguard_interface('wg0')
        self.assertTrue(success, message)
        self.assertIn('192.168.60.0/24', network.route_names())


class AgentRouteSyncTests(RouteSyncCases, TestCase):
    @classmethod
    def setUpClass(cls):
        super().setUpClass()
        cls.cluster_worker = load_cluster_worker()

    def sync(self, network):
        with patch.object(self.cluster_worker.subprocess, 'run', side_effect=network.run):
            self.cluster_worker.sync_interface_routes(network.interface)

    def test_sync_peers_syncs_routes(self):
        network = FakeNetwork('wg0', ['10.188.0.2/32 192.168.60.0/24'], {'10.188.0.0/24': True})
        with patch.object(self.cluster_worker.subprocess, 'run', side_effect=network.run):
            self.cluster_worker.ClusterNodeAgent.sync_peers('wg0', '/etc/wireguard/wg0.conf')
        self.assertIn('192.168.60.0/24', network.route_names())


class RestartInterfacesTests(TestCase):
    def setUp(self):
        user = User.objects.create_user(username='admin', password='unused')
        UserAcl.objects.create(user=user, user_level=50)
        self.client.force_login(user)

    def test_restart_does_not_stop_interface_that_is_not_running(self):
        commands = []

        def run(command, *args, **kwargs):
            commands.append(command if isinstance(command, str) else ' '.join(command))
            if command == ['wg', 'show', 'interfaces']:
                return subprocess.CompletedProcess(command, 0, 'wg0\n', '')
            return subprocess.CompletedProcess(command, 0, '', '')

        with patch('wireguard_tools.views.os.listdir', return_value=['wg0.conf', 'wg1.conf']), \
                patch('wireguard_tools.views.os.path.isfile', return_value=True), \
                patch('wireguard_tools.views.subprocess.run', side_effect=run):
            response = self.client.get('/tools/restart_wireguard/')

        self.assertIn('wg-quick down wg0', commands)
        self.assertNotIn('wg-quick down wg1', commands)
        self.assertIn('wg-quick up wg1', commands)
        message_texts = [str(message) for message in get_messages(response.wsgi_request)]
        self.assertFalse([text for text in message_texts if 'Error' in text], message_texts)


class ReloadFailureTests(TestCase):
    def setUp(self):
        self.instance = WireGuardInstance.objects.create(
            instance_id=0, private_key='private-0', public_key='public-0', hostname='primary.example.test',
            listen_port=51820, address='10.188.0.1', pending_changes=False,
        )

    def test_failed_reload_marks_instance_pending(self):
        with patch('wireguard_tools.functions.reload_wireguard_interface', return_value=(False, 'syncconf failed')):
            success, message = functions.func_reload_wireguard_interface(self.instance)
        self.assertFalse(success)
        self.assertTrue(self.instance.pending_changes)
        self.instance.refresh_from_db()
        self.assertTrue(self.instance.pending_changes)

    def test_successful_reload_keeps_instance_applied(self):
        with patch('wireguard_tools.functions.reload_wireguard_interface', return_value=(True, 'wg0 reloaded')):
            success, message = functions.func_reload_wireguard_interface(self.instance)
        self.assertTrue(success)
        self.instance.refresh_from_db()
        self.assertFalse(self.instance.pending_changes)

    def test_route_error_fails_the_reload(self):
        network = FakeNetwork('wg0', ['10.188.0.2/32 192.168.60.0/24'], {'10.188.0.0/24': True})

        def run(command, *args, **kwargs):
            if 'replace' in command:
                return subprocess.CompletedProcess(command, 2, '', 'RTNETLINK answers: failure')
            return network.run(command)

        with patch('wireguard_tools.functions.os.path.exists', return_value=True), \
                patch('wireguard_tools.functions.os.remove'), \
                patch('builtins.open'), \
                patch('wireguard_tools.functions.subprocess.run', side_effect=run):
            success, message = functions.func_reload_wireguard_interface(self.instance)
        self.assertFalse(success)
        self.assertIn('192.168.60.0/24', message)
        self.instance.refresh_from_db()
        self.assertTrue(self.instance.pending_changes)


class AgentInterfaceFailureTests(TestCase):
    """A failed interface must be applied again on the next attempt, even if the content did not change."""

    OLD_CONFIG = '[Interface]\nListenPort = 51820\n\n[Peer]\nPublicKey = peer-a\nAllowedIPs = 10.188.0.2/32\n'
    NEW_CONFIG = OLD_CONFIG + 'AllowedIPs = 192.168.60.0/24\n'

    @classmethod
    def setUpClass(cls):
        super().setUpClass()
        cls.cluster_worker = load_cluster_worker()

    def setUp(self):
        temp_dir = tempfile.TemporaryDirectory()
        self.addCleanup(temp_dir.cleanup)
        self.config_path = os.path.join(temp_dir.name, 'wg0.conf')
        with open(self.config_path, 'w', encoding='utf-8') as config_file:
            config_file.write(self.OLD_CONFIG)
        for name, value in (
            ('WIREGUARD_DIR', temp_dir.name), ('interface_is_up', lambda interface: True),
            # Never touch the qdiscs of the interfaces of the machine that runs the tests
            ('apply_speed_limits', lambda interface, config_path: []),
            ('remove_speed_limits', lambda interface: None),
        ):
            patcher = patch.object(self.cluster_worker, name, value)
            patcher.start()
            self.addCleanup(patcher.stop)
        self.agent = self.cluster_worker.ClusterNodeAgent()
        self.section = {'files': {'wg0.conf': self.NEW_CONFIG}}

    def read_config(self):
        with open(self.config_path, encoding='utf-8') as config_file:
            return config_file.read()

    def test_failed_sync_restores_previous_content_and_retries(self):
        SectionError = self.cluster_worker.SectionError
        with patch.object(self.cluster_worker.ClusterNodeAgent, 'sync_peers', side_effect=SectionError('wg0 routes: failure')):
            with self.assertRaises(SectionError):
                self.agent.apply_wireguard(self.section)
        self.assertEqual(self.read_config(), self.OLD_CONFIG)

        with patch.object(self.cluster_worker.ClusterNodeAgent, 'sync_peers') as sync_peers:
            self.agent.apply_wireguard(self.section)
        sync_peers.assert_called_once_with('wg0', self.config_path)
        self.assertEqual(self.read_config(), self.NEW_CONFIG)

    def test_unchanged_content_is_not_applied_again(self):
        with patch.object(self.cluster_worker.ClusterNodeAgent, 'sync_peers') as sync_peers:
            self.agent.apply_wireguard(self.section)
            self.agent.apply_wireguard(self.section)
        sync_peers.assert_called_once()
