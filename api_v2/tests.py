import json
from unittest.mock import patch

from django.test import TestCase

from api_v2.models import ApiKey
from dns.models import DNSSettings, StaticHost


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
