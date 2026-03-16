import tempfile
import unittest
from pathlib import Path

import pyotp
from auth_gateway.config_loader import load_runtime_config
from auth_gateway.services.policy_engine import build_effective_policy, evaluate_ip_rules
from auth_gateway.services.resolver import resolve_request_context
from auth_gateway.services.totp_service import verify_totp


class AuthGatewayConfigTests(unittest.TestCase):
    def test_existing_config_loads_and_resolves_routes(self):
        config_dir = Path(__file__).resolve().parents[2] / "caddy" / "config_files"
        runtime_config = load_runtime_config(config_dir)

        context = resolve_request_context(runtime_config, "app1-dev.local", "/admin/settings")
        self.assertIsNotNone(context)
        self.assertEqual(context.policy_name, "senha-totp")

        context = resolve_request_context(runtime_config, "app1-dev.local", "/api/status")
        self.assertIsNotNone(context)
        self.assertEqual(context.policy_name, "ips-conhecidos")

        policy = build_effective_policy(runtime_config, "senha-totp")
        self.assertIsNotNone(policy)
        self.assertEqual(policy.required_factors, ["totp", "password"])

    def test_invalid_oidc_provider_fails_loudly(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            tmp_path = Path(tmpdir)
            (tmp_path / "wireguard_webadmin.json").write_text(
                '{"entries":[{"id":"app","name":"app","hosts":["app.local"],"upstream":"http://app"}]}',
                encoding="utf-8",
            )
            (tmp_path / "auth_policies.json").write_text(
                '{"auth_methods":{"oidc":{"type":"oidc","provider":"https://bad..host","client_id":"a","client_secret":"b","allowed_domains":[],"allowed_emails":[]}},"policies":{"default":{"policy_type":"protected","groups":[],"methods":["oidc"]}}}',
                encoding="utf-8",
            )
            (tmp_path / "routes.json").write_text(
                '{"entries":{"app":{"routes":[],"default_policy":"default"}}}',
                encoding="utf-8",
            )

            with self.assertRaises(ValueError):
                load_runtime_config(tmp_path)

    def test_ip_rules_respect_json_order(self):
        config_dir = Path(__file__).resolve().parents[2] / "caddy" / "config_files"
        runtime_config = load_runtime_config(config_dir)
        method = runtime_config.auth_methods["iplist1"]
        self.assertTrue(evaluate_ip_rules("192.168.0.8", method.rules))
        self.assertTrue(evaluate_ip_rules("192.168.0.12", method.rules))
        self.assertFalse(evaluate_ip_rules("10.10.10.10", method.rules))

    def test_totp_verification_accepts_valid_tokens(self):
        secret = "JBSWY3DPEHPK3PXP"
        token = pyotp.TOTP(secret).now()
        self.assertTrue(verify_totp(secret, token))


if __name__ == "__main__":
    unittest.main()
