import json

from django.test import TestCase

from api_v2.models import ApiKey
from wireguard.models import Peer, PeerAllowedIP, WireGuardInstance
from wireguard_peer.forms import PeerAllowedIPForm


def create_instance(instance_id):
    return WireGuardInstance.objects.create(
        instance_id=instance_id, private_key=f'private-{instance_id}', public_key=f'public-{instance_id}',
        hostname='primary.example.test', listen_port=51820 + instance_id, address=f'10.188.{instance_id}.1',
    )


def create_peer(instance, name, address):
    peer = Peer.objects.create(
        name=name, public_key=f'public-{name}', pre_shared_key=f'psk-{name}', wireguard_instance=instance,
    )
    PeerAllowedIP.objects.create(peer=peer, config_file='server', priority=0, allowed_ip=address, netmask=32)
    return peer


class NetworkSetupMixin:
    """wg0 already routes 192.168.74.0/24 to one of its peers."""

    def setUp(self):
        super().setUp()
        self.wg0 = create_instance(0)
        self.wg1 = create_instance(1)
        self.peer_wg0 = create_peer(self.wg0, 'peer-wg0', '10.188.0.2')
        self.peer_wg0_other = create_peer(self.wg0, 'peer-wg0-other', '10.188.0.3')
        self.peer_wg1 = create_peer(self.wg1, 'peer-wg1', '10.188.1.2')
        self.network_wg0 = PeerAllowedIP.objects.create(
            peer=self.peer_wg0, config_file='server', priority=1, allowed_ip='192.168.74.0', netmask=24,
        )


class NetworkInOtherInstanceTests(NetworkSetupMixin, TestCase):
    """The same network cannot be routed to peers of two instances: the second interface would fail to start."""

    def form(self, peer, allowed_ip, netmask, config_file='server', instance=None):
        return PeerAllowedIPForm(
            data={'allowed_ip': allowed_ip, 'netmask': netmask, 'priority': 1},
            instance=instance, current_peer=peer, config_file=config_file,
        )

    def test_form_refuses_network_of_other_instance(self):
        form = self.form(self.peer_wg1, '192.168.74.0', 24)
        self.assertFalse(form.is_valid())
        self.assertIn('peer-wg0', str(form.errors))
        self.assertIn('wg0', str(form.errors))

    def test_form_refuses_same_network_written_with_host_address(self):
        self.assertFalse(self.form(self.peer_wg1, '192.168.74.9', 24).is_valid())

    def test_form_accepts_different_prefix(self):
        self.assertTrue(self.form(self.peer_wg1, '192.168.74.128', 25).is_valid())

    def test_form_accepts_same_instance_and_editing_itself(self):
        self.assertTrue(self.form(self.peer_wg0_other, '192.168.74.0', 24).is_valid())
        self.assertTrue(self.form(self.peer_wg0, '192.168.74.0', 24, instance=self.network_wg0).is_valid())

    def test_form_does_not_check_client_routes(self):
        self.assertTrue(self.form(self.peer_wg1, '192.168.74.0', 24, config_file='client').is_valid())


class NetworkInOtherInstanceApiTests(NetworkSetupMixin, TestCase):
    def setUp(self):
        super().setUp()
        self.api_key = ApiKey.objects.create(name='tests')

    def call(self, method, payload):
        payload = dict(payload, instance='wg1', skip_reload=True)
        return getattr(self.client, method)(
            '/api/v2/manage_peer/', data=json.dumps(payload), content_type='application/json',
            HTTP_TOKEN=str(self.api_key.token),
        )

    def test_api_create_refuses_network_of_other_instance(self):
        peer_count = Peer.objects.count()
        response = self.call('post', {'name': 'api-peer', 'announced_networks': ['192.168.74.0/24']})
        self.assertEqual(response.status_code, 400)
        self.assertIn('wg0', response.json()['error_message'])
        self.assertEqual(Peer.objects.count(), peer_count)

    def test_api_update_refuses_network_of_other_instance(self):
        response = self.call('put', {
            'peer_public_key': self.peer_wg1.public_key, 'announced_networks': ['192.168.75.0/24', '192.168.74.0/24'],
        })
        self.assertEqual(response.status_code, 400)
        self.assertFalse(PeerAllowedIP.objects.filter(peer=self.peer_wg1, priority__gte=1).exists())

    def test_api_update_accepts_free_network(self):
        response = self.call('put', {'peer_public_key': self.peer_wg1.public_key, 'announced_networks': ['192.168.75.0/24']})
        self.assertEqual(response.status_code, 200, response.content)
        self.assertTrue(PeerAllowedIP.objects.filter(peer=self.peer_wg1, allowed_ip='192.168.75.0', netmask=24).exists())
