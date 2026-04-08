import json
from unittest.mock import patch

from django.test import TestCase

from api_v2.models import ApiKey
from dns.models import DNSSettings, StaticHost
from vpn_invite.models import InviteSettings, PeerInvite
from wireguard.models import Peer, WireGuardInstance
from wireguard_tools.models import EmailSettings

class ApiV2ManageDnsRecordTests(TestCase):
    def setUp(self):
        self.api_key = ApiKey.objects.create(name="dns-test-key", enabled=True)
        self.url = "/api/v2/manage_dns_record/"

    @staticmethod
    def _fake_export_dns_configuration():
        dns_settings, dns_settings_created = DNSSettings.objects.get_or_create(name="dns_settings")
        dns_settings.pending_changes = False
        dns_settings.save(update_fields=["pending_changes", "updated"])

    @patch("api_v2.views_api.export_dns_configuration")
    def test_post_creates_record(self, mock_export):
        response = self.client.post(
            self.url,
            data=json.dumps({
                "hostname": "App.Example.com",
                "ip_address": "10.20.30.40",
                "skip_reload": True,
            }),
            content_type="application/json",
            HTTP_TOKEN=str(self.api_key.token),
        )

        self.assertEqual(response.status_code, 201)
        body = response.json()
        self.assertEqual(body["hostname"], "app.example.com")
        self.assertEqual(body["ip_address"], "10.20.30.40")
        mock_export.assert_not_called()
        self.assertTrue(StaticHost.objects.filter(hostname="app.example.com").exists())

    @patch("api_v2.views_api.export_dns_configuration")
    def test_post_fails_if_record_exists(self, mock_export):
        StaticHost.objects.create(hostname="app.example.com", ip_address="10.20.30.40")

        response = self.client.post(
            self.url,
            data=json.dumps({
                "hostname": "app.example.com",
                "ip_address": "10.20.30.99",
                "skip_reload": False,
            }),
            content_type="application/json",
            HTTP_TOKEN=str(self.api_key.token),
        )

        self.assertEqual(response.status_code, 400)
        self.assertIn("already exists", response.json()["error_message"])
        self.assertEqual(str(StaticHost.objects.get(hostname="app.example.com").ip_address), "10.20.30.40")
        mock_export.assert_not_called()

    @patch("api_v2.views_api.export_dns_configuration")
    def test_put_upserts_existing_record(self, mock_export):
        mock_export.side_effect = self._fake_export_dns_configuration
        StaticHost.objects.create(hostname="app.example.com", ip_address="10.20.30.40")
        DNSSettings.objects.create(name="dns_settings", pending_changes=True)

        response = self.client.put(
            self.url,
            data=json.dumps({
                "hostname": "app.example.com",
                "ip_address": "10.20.30.41",
                "skip_reload": False,
            }),
            content_type="application/json",
            HTTP_TOKEN=str(self.api_key.token),
        )

        self.assertEqual(response.status_code, 200)
        self.assertEqual(str(StaticHost.objects.get(hostname="app.example.com").ip_address), "10.20.30.41")
        self.assertEqual(StaticHost.objects.filter(hostname="app.example.com").count(), 1)
        self.assertFalse(DNSSettings.objects.get(name="dns_settings").pending_changes)
        mock_export.assert_called_once()

    @patch("api_v2.views_api.export_dns_configuration")
    def test_put_upserts_missing_record_as_create(self, mock_export):
        mock_export.side_effect = self._fake_export_dns_configuration

        response = self.client.put(
            self.url,
            data=json.dumps({
                "hostname": "new.example.com",
                "ip_address": "10.20.30.50",
                "skip_reload": False,
            }),
            content_type="application/json",
            HTTP_TOKEN=str(self.api_key.token),
        )

        self.assertEqual(response.status_code, 201)
        self.assertTrue(StaticHost.objects.filter(hostname="new.example.com").exists())
        mock_export.assert_called_once()

    @patch("api_v2.views_api.export_dns_configuration")
    def test_delete_deletes_record_and_does_not_require_ip(self, mock_export):
        StaticHost.objects.create(hostname="del.example.com", ip_address="10.1.2.3")

        response = self.client.delete(
            self.url,
            data=json.dumps({
                "hostname": "del.example.com",
                "skip_reload": True,
            }),
            content_type="application/json",
            HTTP_TOKEN=str(self.api_key.token),
        )

        self.assertEqual(response.status_code, 200)
        self.assertFalse(StaticHost.objects.filter(hostname="del.example.com").exists())
        mock_export.assert_not_called()

class ApiV2PeerInviteTests(TestCase):
    def setUp(self):
        self.api_key = ApiKey.objects.create(name="invite-test-key", enabled=True)
        self.wireguard_instance = WireGuardInstance.objects.create(
            instance_id=0,
            name="wg0",
            address="10.0.0.1",
            netmask=24,
            listen_port=51820,
            public_key="public_key",
            private_key="private_key"
        )
        self.api_key.allowed_instances.add(self.wireguard_instance)

        self.peer = Peer.objects.create(
            wireguard_instance=self.wireguard_instance,
            name="Test Peer",
            public_key="peer_public_key",
            private_key="peer_private_key"
        )

        # Create invite settings
        InviteSettings.objects.create(
            name='default_settings',
            invite_url='https://vpn.example.com/invite/',
            invite_expiration=30,
            required_user_level=50,
            invite_email_enabled=True
        )

        # Create email settings
        EmailSettings.objects.create(
            name='email_settings',
            enabled=True,
            smtp_host='smtp.example.com',
            smtp_port=587,
            smtp_username='user',
            smtp_password='password',
            smtp_from_address='vpn@example.com',
            smtp_encryption='tls'
        )

        self.url = "/api/v2/peer_invite/"

    def test_create_invite_without_email(self):
        response = self.client.post(
            self.url,
            data=json.dumps({
                "instance": "wg0",
                "peer_uuid": str(self.peer.uuid)
            }),
            content_type="application/json",
            HTTP_TOKEN=str(self.api_key.token),
        )

        self.assertEqual(response.status_code, 200)
        body = response.json()
        self.assertEqual(body["status"], "success")
        self.assertEqual(body["message"], "Invitation created successfully.")
        self.assertIn("invite_data", body)
        self.assertIn("url", body["invite_data"])
        self.assertIn("password", body["invite_data"])
        self.assertIn("expiration", body["invite_data"])

        # Verify invite was created
        self.assertTrue(PeerInvite.objects.filter(peer=self.peer).exists())

    def test_create_invite_with_invalid_peer_uuid(self):
        response = self.client.post(
            self.url,
            data=json.dumps({
                "instance": "wg0",
                "peer_uuid": "00000000-0000-0000-0000-000000000000"
            }),
            content_type="application/json",
            HTTP_TOKEN=str(self.api_key.token),
        )

        self.assertEqual(response.status_code, 404)
        body = response.json()
        self.assertEqual(body["status"], "error")
        self.assertEqual(body["error_message"], "Peer not found.")

    def test_create_invite_without_peer_uuid(self):
        response = self.client.post(
            self.url,
            data=json.dumps({
                "instance": "wg0"
            }),
            content_type="application/json",
            HTTP_TOKEN=str(self.api_key.token),
        )

        self.assertEqual(response.status_code, 400)
        body = response.json()
        self.assertEqual(body["status"], "error")
        self.assertEqual(body["error_message"], "peer_uuid is required.")

    def test_create_invite_with_invalid_instance(self):
        response = self.client.post(
            self.url,
            data=json.dumps({
                "instance": "wg999",
                "peer_uuid": str(self.peer.uuid)
            }),
            content_type="application/json",
            HTTP_TOKEN=str(self.api_key.token),
        )

        self.assertEqual(response.status_code, 400)
        body = response.json()
        self.assertEqual(body["status"], "error")
        self.assertEqual(body["error_message"], "Invalid or missing WireGuard instance.")

    @patch("wgwadmlibrary.tools.send_email")
    def test_create_invite_with_email(self, mock_send_email):
        mock_send_email.return_value = ('success', 'Email sent successfully.')

        response = self.client.post(
            self.url,
            data=json.dumps({
                "instance": "wg0",
                "peer_uuid": str(self.peer.uuid),
                "email": "user@example.com"
            }),
            content_type="application/json",
            HTTP_TOKEN=str(self.api_key.token),
        )

        self.assertEqual(response.status_code, 200)
        body = response.json()
        self.assertEqual(body["status"], "success")
        self.assertEqual(body["message"], "Invitation created and email sent successfully.")
        self.assertIn("invite_data", body)

        # Verify email was sent
        mock_send_email.assert_called_once()

    @patch("wgwadmlibrary.tools.send_email")
    def test_create_invite_with_email_failure(self, mock_send_email):
        mock_send_email.return_value = ('error', 'SMTP server not available')

        response = self.client.post(
            self.url,
            data=json.dumps({
                "instance": "wg0",
                "peer_uuid": str(self.peer.uuid),
                "email": "user@example.com"
            }),
            content_type="application/json",
            HTTP_TOKEN=str(self.api_key.token),
        )

        self.assertEqual(response.status_code, 400)
        body = response.json()
        self.assertEqual(body["status"], "error")
        self.assertIn("email failed", body["error_message"])
        self.assertIn("invite_data", body)

    def test_create_invite_without_invite_settings(self):
        InviteSettings.objects.all().delete()

        response = self.client.post(
            self.url,
            data=json.dumps({
                "instance": "wg0",
                "peer_uuid": str(self.peer.uuid)
            }),
            content_type="application/json",
            HTTP_TOKEN=str(self.api_key.token),
        )

        self.assertEqual(response.status_code, 400)
        body = response.json()
        self.assertEqual(body["status"], "error")
        self.assertEqual(body["error_message"], "VPN Invite not configured.")
