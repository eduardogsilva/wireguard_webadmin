import json
from datetime import timedelta
from unittest.mock import patch

from django.test import TestCase, override_settings
from django.utils import timezone

from api_v2.models import ApiKey
from vpn_invite.models import InviteSettings, PeerInvite
from cluster.models import ClusterSettings, Worker
from cluster.tests import create_instance
from dns.models import DNSSettings, StaticHost
from wireguard.models import Peer, WireGuardInstance


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

        with self.captureOnCommitCallbacks(execute=True):
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

        with self.captureOnCommitCallbacks(execute=True):
            response = self.client.put(
                self.url,
                data=json.dumps({
                    "hostname": "new.example.com",
                    "ip_address": "10.20.30.50",
                    "skip_reload": False,
                    "create_if_missing": True,
                }),
                content_type="application/json",
                HTTP_TOKEN=str(self.api_key.token),
            )

        self.assertEqual(response.status_code, 201)
        self.assertTrue(StaticHost.objects.filter(hostname="new.example.com").exists())
        mock_export.assert_called_once()

    @patch("api_v2.views_api.export_dns_configuration")
    def test_put_missing_record_without_create_if_missing_returns_404(self, mock_export):
        with self.captureOnCommitCallbacks(execute=True):
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

        self.assertEqual(response.status_code, 404)
        self.assertFalse(StaticHost.objects.filter(hostname="new.example.com").exists())
        mock_export.assert_not_called()

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


@override_settings(WIREGUARD_STATUS_CACHE_ENABLED=True, CADDY_ENABLED=True)
class ApiV2ManageClusterTests(TestCase):
    status_url = "/api/v2/manage_cluster/status/"
    manage_url = "/api/v2/manage_cluster/manage_status/"

    def setUp(self):
        ClusterSettings.objects.update_or_create(name="cluster_settings", defaults={"enabled": True})
        self.api_key = ApiKey.objects.create(name="cluster-key", manage_cluster=True)
        self.node_a = Worker.objects.create(name="node-a")
        self.node_b = Worker.objects.create(name="node-b", enabled=False)
        self.instance = create_instance(0)
        WireGuardInstance.objects.update(pending_changes=False)

        self.calls = []
        self.stop_errors = []
        for name, value in (
            ("running_wireguard_interfaces", lambda: ["wg0"]),
            ("start_primary_interfaces", self.record("start")),
            ("stop_primary_interfaces", self.record("stop")),
            ("apply_caddy_config", self.record("export")),
        ):
            patcher = patch(f"api_v2.views_api.{name}", value)
            patcher.start()
            self.addCleanup(patcher.stop)

    def record(self, name):
        def call():
            self.calls.append(name)
            return list(self.stop_errors) if name == "stop" else []
        return call

    def manage(self, payload, api_key=None, method="put"):
        return getattr(self.client, method)(
            self.manage_url, data=json.dumps(payload), content_type="application/json",
            HTTP_TOKEN=str((api_key or self.api_key).token),
        )

    def assert_unchanged(self):
        self.assertTrue(Worker.objects.get(pk=self.node_a.pk).enabled)
        self.assertFalse(Worker.objects.get(pk=self.node_b.pk).enabled)
        self.assertTrue(ClusterSettings.objects.get(name="cluster_settings").primary_enable_wireguard)
        self.assertEqual(self.calls, [])

    def test_api_key_needs_manage_cluster(self):
        plain_key = ApiKey.objects.create(name="plain-key")
        self.assertEqual(self.client.get(self.status_url).status_code, 403)
        self.assertEqual(self.client.get(self.status_url, HTTP_TOKEN=str(plain_key.token)).status_code, 403)
        response = self.manage({"workers": {str(self.node_a.uuid): False}}, api_key=plain_key)
        self.assertEqual(response.status_code, 403)
        self.assertIn("not allowed to manage the cluster", response.json()["error_message"])
        self.assert_unchanged()

    def test_status_lists_cluster_and_workers_by_uuid(self):
        response = self.client.get(self.status_url, HTTP_TOKEN=str(self.api_key.token))
        self.assertEqual(response.status_code, 200)
        body = response.json()
        self.assertEqual(body["cluster"], {
            "enabled": True, "mode": "mirror", "primary_wireguard": True, "primary_running_interfaces": ["wg0"],
        })
        self.assertEqual(body["workers"][str(self.node_a.uuid)]["name"], "node-a")
        self.assertFalse(body["workers"][str(self.node_b.uuid)]["enabled"])
        self.assertIsNone(body["workers"][str(self.node_b.uuid)]["sync_state"])

    def test_workers_and_primary_change_in_a_single_request(self):
        response = self.manage({
            "workers": {str(self.node_a.uuid): False, str(self.node_b.uuid): True}, "primary_wireguard": False,
        })
        self.assertEqual(response.status_code, 200)
        body = response.json()
        self.assertEqual(body["workers"][str(self.node_a.uuid)], {"name": "node-a", "enabled": False, "changed": True})
        self.assertEqual(body["workers"][str(self.node_b.uuid)], {"name": "node-b", "enabled": True, "changed": True})
        self.assertEqual(body["primary_wireguard"], {"enabled": False, "changed": True})
        self.assertTrue(body["apply"]["success"])
        self.assertFalse(Worker.objects.get(pk=self.node_a.pk).enabled)
        self.assertTrue(Worker.objects.get(pk=self.node_b.pk).enabled)
        self.assertFalse(ClusterSettings.primary_serves_clients())
        self.assertEqual(self.calls, ["export", "stop"])
        self.instance.refresh_from_db()
        self.assertFalse(self.instance.pending_changes)

        # The same request again changes nothing
        self.calls.clear()
        body = self.manage({"workers": {str(self.node_a.uuid): False}, "primary_wireguard": False}).json()
        self.assertFalse(body["workers"][str(self.node_a.uuid)]["changed"])
        self.assertFalse(body["primary_wireguard"]["changed"])
        self.assertEqual(self.calls, [])

    def test_enabling_the_primary_starts_its_interfaces(self):
        ClusterSettings.objects.filter(name="cluster_settings").update(primary_enable_wireguard=False)
        response = self.manage({"primary_wireguard": True}, method="post")
        self.assertEqual(response.status_code, 200)
        self.assertEqual(self.calls, ["export", "start"])
        self.assertTrue(ClusterSettings.primary_serves_clients())

    def test_skip_reload_only_marks_the_instances_pending(self):
        response = self.manage({"primary_wireguard": False, "skip_reload": True})
        self.assertEqual(response.status_code, 200)
        self.assertEqual(self.calls, [])
        self.instance.refresh_from_db()
        self.assertTrue(self.instance.pending_changes)

    def test_worker_changes_do_not_touch_the_primary_interfaces(self):
        response = self.manage({"workers": {str(self.node_a.uuid): False}})
        self.assertEqual(response.status_code, 200)
        self.assertNotIn("primary_wireguard", response.json())
        self.assertEqual(self.calls, [])

    def test_invalid_requests_change_nothing(self):
        for payload in (
            {},
            {"workers": {}},
            {"workers": {"00000000-0000-0000-0000-000000000000": False}, "primary_wireguard": False},
            {"workers": {"node-a": False}},
            {"workers": {str(self.node_a.uuid): "no"}},
            {"workers": {str(self.node_b.uuid): True}, "primary_wireguard": 0},
        ):
            response = self.manage(payload)
            self.assertEqual(response.status_code, 400, payload)
        self.assert_unchanged()

    def test_primary_follows_the_cluster_settings_form_rules(self):
        ClusterSettings.objects.filter(name="cluster_settings").update(cluster_mode="distributed")
        response = self.manage({"workers": {str(self.node_a.uuid): False}, "primary_wireguard": False})
        self.assertEqual(response.status_code, 400)
        self.assertIn("only be disabled in mirror mode", response.json()["error_message"])
        self.assert_unchanged()

    def test_changes_require_an_enabled_cluster(self):
        ClusterSettings.objects.filter(name="cluster_settings").update(enabled=False)
        response = self.manage({"workers": {str(self.node_a.uuid): False}})
        self.assertEqual(response.status_code, 400)
        self.assertEqual(response.json()["error_message"], "The cluster is not enabled.")
        self.assert_unchanged()

    def test_apply_failure_keeps_the_saved_changes_pending(self):
        self.stop_errors = [("wg0", "device busy")]
        response = self.manage({"primary_wireguard": False})
        self.assertEqual(response.status_code, 500)
        self.assertIn("saved but apply failed: wg0: device busy", response.json()["error_message"])
        self.assertFalse(ClusterSettings.objects.get(name="cluster_settings").primary_enable_wireguard)
        self.instance.refresh_from_db()
        self.assertTrue(self.instance.pending_changes)

    def test_other_methods_are_not_allowed(self):
        response = self.client.delete(self.manage_url, HTTP_TOKEN=str(self.api_key.token))
        self.assertEqual(response.status_code, 405)
        response = self.client.put(self.status_url, HTTP_TOKEN=str(self.api_key.token))
        self.assertEqual(response.status_code, 405)


class ApiV2PeerInviteTests(TestCase):
    url = "/api/v2/peer_invite/"

    def setUp(self):
        self.instance = create_instance(0)
        self.other_instance = create_instance(1)
        self.api_key = ApiKey.objects.create(name="invite-test-key", enabled=True)
        self.api_key.allowed_instances.add(self.instance)
        self.peer = Peer.objects.create(
            wireguard_instance=self.instance, name="Test Peer", public_key="peer-public", private_key="peer-private",
        )
        self.invite_settings = InviteSettings.objects.create(
            name="default_settings", invite_url="https://vpn.example.com/invite/", invite_expiration=30,
        )

    def request(self, payload, api_key=None):
        return self.client.post(
            self.url, data=json.dumps(payload), content_type="application/json",
            HTTP_TOKEN=str((api_key or self.api_key).token),
        )

    def test_creates_invite(self):
        response = self.request({"instance": "wg0", "peer_uuid": str(self.peer.uuid)})
        self.assertEqual(response.status_code, 200)
        body = response.json()
        self.assertEqual(body["message"], "Invite created.")
        invite = PeerInvite.objects.get(peer=self.peer)
        self.assertEqual(body["invite_data"]["uuid"], str(invite.uuid))
        self.assertEqual(body["invite_data"]["url"], f"https://vpn.example.com/invite/?token={invite.uuid}&")
        self.assertEqual(body["invite_data"]["password"], invite.invite_password)

    def test_selects_peer_by_public_key(self):
        response = self.request({"instance": "wg0", "peer_public_key": "peer-public"})
        self.assertEqual(response.status_code, 200)
        self.assertTrue(PeerInvite.objects.filter(peer=self.peer).exists())

    def test_existing_invite_is_renewed(self):
        self.request({"instance": "wg0", "peer_uuid": str(self.peer.uuid)})
        invite = PeerInvite.objects.get(peer=self.peer)
        PeerInvite.objects.filter(pk=invite.pk).update(
            invite_expiration=invite.invite_expiration - timedelta(minutes=20)
        )
        response = self.request({"instance": "wg0", "peer_uuid": str(self.peer.uuid)})
        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.json()["message"], "Existing invite renewed.")
        renewed = PeerInvite.objects.get(peer=self.peer)
        self.assertEqual(renewed.uuid, invite.uuid)
        self.assertGreater(renewed.invite_expiration, timezone.now() + timedelta(minutes=25))

    def test_missing_peer_selector(self):
        response = self.request({"instance": "wg0"})
        self.assertEqual(response.status_code, 400)
        self.assertEqual(response.json()["error_message"], "Missing peer selector (peer_uuid or peer_public_key).")

    def test_unknown_peer(self):
        for peer_uuid in ("00000000-0000-0000-0000-000000000000", "not-a-uuid"):
            response = self.request({"instance": "wg0", "peer_uuid": peer_uuid})
            self.assertEqual(response.status_code, 404)
            self.assertEqual(response.json()["error_message"], "Peer not found.")

    def test_invalid_instance(self):
        response = self.request({"instance": "wg999", "peer_uuid": str(self.peer.uuid)})
        self.assertEqual(response.status_code, 400)
        self.assertEqual(response.json()["error_message"], "Invalid or missing WireGuard instance.")

    def test_peer_of_another_instance_is_not_found(self):
        unrestricted_key = ApiKey.objects.create(name="unrestricted-key", enabled=True)
        response = self.request({"instance": "wg1", "peer_uuid": str(self.peer.uuid)}, api_key=unrestricted_key)
        self.assertEqual(response.status_code, 404)
        self.assertFalse(PeerInvite.objects.exists())

    def test_api_key_without_access_to_the_instance(self):
        other_peer = Peer.objects.create(
            wireguard_instance=self.other_instance, name="Other Peer", public_key="other-public", private_key="other-private",
        )
        response = self.request({"instance": "wg1", "peer_uuid": str(other_peer.uuid)})
        self.assertEqual(response.status_code, 403)
        self.assertFalse(PeerInvite.objects.exists())

    def test_peer_with_endpoint_is_refused(self):
        Peer.objects.filter(pk=self.peer.pk).update(endpoint="remote.example.com:51820")
        response = self.request({"instance": "wg0", "peer_uuid": str(self.peer.uuid)})
        self.assertEqual(response.status_code, 400)
        self.assertEqual(response.json()["error_message"], "Peers with an endpoint have no client configuration to share.")
        self.assertFalse(PeerInvite.objects.exists())

    @patch("api_v2.views_api.send_email")
    def test_email_disabled_in_invite_settings(self, mock_send_email):
        InviteSettings.objects.filter(pk=self.invite_settings.pk).update(invite_email_enabled=False)
        response = self.request({"instance": "wg0", "peer_uuid": str(self.peer.uuid), "email": "user@example.com"})
        self.assertEqual(response.status_code, 400)
        self.assertEqual(response.json()["error_message"], "Email invites are disabled in the VPN invite settings.")
        self.assertFalse(PeerInvite.objects.exists())
        mock_send_email.assert_not_called()

    @patch("api_v2.views_api.send_email")
    def test_sends_invite_by_email(self, mock_send_email):
        mock_send_email.return_value = ("success", "Email sent successfully.")
        response = self.request({"instance": "wg0", "peer_uuid": str(self.peer.uuid), "email": "user@example.com"})
        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.json()["message"], "Invite created. Email sent to user@example.com.")
        invite_data = response.json()["invite_data"]
        mock_send_email.assert_called_once_with("user@example.com", invite_data["email_subject"], invite_data["email_body"])

    @patch("api_v2.views_api.send_email")
    def test_email_failure_keeps_the_invite(self, mock_send_email):
        mock_send_email.return_value = ("error", "SMTP server not available")
        response = self.request({"instance": "wg0", "peer_uuid": str(self.peer.uuid), "email": "user@example.com"})
        self.assertEqual(response.status_code, 500)
        body = response.json()
        self.assertEqual(body["error_message"], "Invite created, but the email could not be sent: SMTP server not available")
        self.assertEqual(body["invite_data"]["uuid"], str(PeerInvite.objects.get(peer=self.peer).uuid))

    def test_other_methods_are_not_allowed(self):
        response = self.client.get(self.url, HTTP_TOKEN=str(self.api_key.token))
        self.assertEqual(response.status_code, 405)
