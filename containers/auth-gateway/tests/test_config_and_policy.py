import importlib.util
import tempfile
import unittest
from pathlib import Path

import pyotp
from auth_gateway.config_loader import load_runtime_config
from auth_gateway.services.policy_engine import build_effective_policy, evaluate_ip_rules
from auth_gateway.services.resolver import resolve_request_context
from auth_gateway.services.totp_service import verify_totp

_PROCESS_CONFIG_PATH = Path(__file__).resolve().parents[2] / "caddy" / "process_config.py"
_PROCESS_CONFIG_SPEC = importlib.util.spec_from_file_location("caddy_process_config", _PROCESS_CONFIG_PATH)
_PROCESS_CONFIG_MODULE = importlib.util.module_from_spec(_PROCESS_CONFIG_SPEC)
assert _PROCESS_CONFIG_SPEC and _PROCESS_CONFIG_SPEC.loader
_PROCESS_CONFIG_SPEC.loader.exec_module(_PROCESS_CONFIG_MODULE)
build_caddyfile = _PROCESS_CONFIG_MODULE.build_caddyfile


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

    def test_caddyfile_uses_boundary_matchers_and_clears_identity_headers(self):
        caddyfile = build_caddyfile(
            apps=[
                {
                    "id": "app-one",
                    "hosts": ["app.example.com"],
                    "upstream": "http://backend:8080",
                }
            ],
            auth_policies={
                "policies": {
                    "public": {"policy_type": "bypass"},
                    "protected": {"policy_type": "protected"},
                }
            },
            routes={
                "entries": {
                    "app-one": {
                        "routes": [
                            {"path_prefix": "/public", "policy": "public"},
                        ],
                        "default_policy": "protected",
                    }
                }
            },
        )

        self.assertIn("@route_app_one_0 {", caddyfile)
        self.assertIn("path /public /public/*", caddyfile)
        self.assertIn("request_header -X-Auth-User", caddyfile)
        self.assertIn("request_header -X-Auth-Email", caddyfile)
        self.assertIn("handle @route_app_one_0 {", caddyfile)
        self.assertNotIn("handle /public*", caddyfile)


if __name__ == "__main__":
    unittest.main()
