from django.contrib.auth.models import User
from django.test import TestCase

from cluster.tests import create_instance
from user_manager.models import UserAcl
from vpn_invite.models import InviteSettings, PeerInvite
from wireguard.models import Peer


class PeerInviteTests(TestCase):
    def setUp(self):
        user = User.objects.create_user(username='admin', password='unused')
        UserAcl.objects.create(user=user, user_level=50)
        self.client.force_login(user)
        InviteSettings.objects.create(name='default_settings', invite_url='https://vpn.example.com/invite/')
        self.peer = Peer.objects.create(
            wireguard_instance=create_instance(0), name='Peer', public_key='peer-public', private_key='peer-private',
        )

    def test_creates_invite(self):
        response = self.client.get('/api/peer_invite/', {'peer': str(self.peer.uuid)})
        self.assertEqual(response.status_code, 200)
        self.assertTrue(PeerInvite.objects.filter(peer=self.peer).exists())

    def test_peer_with_endpoint_is_refused(self):
        Peer.objects.filter(pk=self.peer.pk).update(endpoint='remote.example.com:51820')
        response = self.client.get('/api/peer_invite/', {'peer': str(self.peer.uuid)})
        self.assertEqual(response.status_code, 400)
        self.assertEqual(response.json()['message'], 'Peers with an endpoint have no client configuration to share')
        self.assertFalse(PeerInvite.objects.exists())
