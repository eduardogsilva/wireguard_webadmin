import contextlib
import importlib.util
import io
import json
import os
import tempfile
from pathlib import Path
from unittest.mock import patch

from django.conf import settings
from django.test import TestCase

from app_gateway.caddy_config_export import export_caddy_config
from app_gateway.models import AccessPolicy, Application, ApplicationHost, ApplicationPolicy, ApplicationRoute
from gatekeeper.models import (
    AuthMethod, AuthMethodAllowedDomain, AuthMethodAllowedEmail, GatekeeperGroup, GatekeeperIPAddress, GatekeeperUser
)

AUTH_GATEWAY_FIXTURES_DIR = Path(settings.BASE_DIR) / 'containers' / 'auth-gateway' / 'tests' / 'fixtures' / 'config_files'
UPDATE_FIXTURES_ENV = 'UPDATE_AUTH_GATEWAY_FIXTURES'

# Argon2 hash of "fixture-password". Kept fixed so the exported files are reproducible.
FIXTURE_PASSWORD_HASH = '$argon2id$v=19$m=65536,t=3,p=4$bEzFGMfGGK4rdHKhmwwMqw$1J+Ss48IEK1Q4Vpy0RaS+FHIZOjhjhE4MK5C5pzDzHg'
FIXTURE_GLOBAL_TOTP_SECRET = 'JBSWY3DPEHPK3PXPJBSWY3DPEHPK3PXP'
FIXTURE_USER_TOTP_SECRET = 'GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ'

_WEBADMIN_EXPORT_PATH = Path(settings.BASE_DIR) / 'containers' / 'caddy' / 'export_wireguard_webadmin_config.py'
_WEBADMIN_EXPORT_SPEC = importlib.util.spec_from_file_location('caddy_export_wireguard_webadmin_config', _WEBADMIN_EXPORT_PATH)
_WEBADMIN_EXPORT_MODULE = importlib.util.module_from_spec(_WEBADMIN_EXPORT_SPEC)
_WEBADMIN_EXPORT_SPEC.loader.exec_module(_WEBADMIN_EXPORT_MODULE)


def create_auth_gateway_scenario():
    local_password = AuthMethod.objects.create(display_name='Local Password', auth_type='local_password')
    totp_global = AuthMethod.objects.create(display_name='TOTP Global', auth_type='totp', totp_secret=FIXTURE_GLOBAL_TOTP_SECRET)
    ip_allowlist = AuthMethod.objects.create(display_name='IP Allowlist', auth_type='ip_address')
    ip_empty = AuthMethod.objects.create(display_name='IP Empty', auth_type='ip_address')
    oidc_company = AuthMethod.objects.create(
        display_name='OIDC Company', auth_type='oidc', session_expiration_minutes=2880,
        oidc_provider='https://idp.example.test', oidc_client_id='fixture-client', oidc_client_secret='fixture-client-secret',
    )

    for address, prefix_length, action in (
        ('10.10.0.1', None, 'allow'),
        ('10.20.0.0', 24, 'allow'),
        ('10.20.0.12', None, 'deny'),
        ('10.30.0.15', None, 'allow'),
    ):
        GatekeeperIPAddress.objects.create(auth_method=ip_allowlist, address=address, prefix_length=prefix_length, action=action)

    AuthMethodAllowedDomain.objects.create(auth_method=oidc_company, domain='example.test')
    AuthMethodAllowedEmail.objects.create(auth_method=oidc_company, email='contractor@partner.example.test')

    alice = GatekeeperUser.objects.create(username='alice', email='alice@example.test', password=FIXTURE_PASSWORD_HASH)
    bob = GatekeeperUser.objects.create(username='bob', password=FIXTURE_PASSWORD_HASH, totp_secret=FIXTURE_USER_TOTP_SECRET)
    staff_group = GatekeeperGroup.objects.create(display_name='Staff')
    staff_group.users.add(alice, bob)

    public_policy = AccessPolicy.objects.get(policy_type='public')
    password_totp_policy = AccessPolicy.objects.create(display_name='Password TOTP', policy_type='protected')
    password_totp_policy.groups.add(staff_group)
    password_totp_policy.methods.add(local_password, totp_global)
    staff_password_policy = AccessPolicy.objects.create(display_name='Staff Password', policy_type='protected')
    staff_password_policy.groups.add(staff_group)
    staff_password_policy.methods.add(local_password)
    totp_only_policy = AccessPolicy.objects.create(display_name='TOTP Only', policy_type='protected')
    totp_only_policy.methods.add(totp_global)
    trusted_ips_policy = AccessPolicy.objects.create(display_name='Trusted IPs', policy_type='protected')
    trusted_ips_policy.methods.add(ip_allowlist)
    empty_ip_list_policy = AccessPolicy.objects.create(display_name='Empty IP List', policy_type='protected')
    empty_ip_list_policy.methods.add(ip_empty)
    oidc_company_policy = AccessPolicy.objects.create(display_name='OIDC Company', policy_type='protected')
    oidc_company_policy.methods.add(oidc_company)

    dashboard = Application.objects.create(display_name='Dashboard', upstream='http://10.0.0.10:3000')
    ApplicationHost.objects.create(application=dashboard, hostname='dashboard.example.test')
    ApplicationPolicy.objects.create(application=dashboard, default_policy=staff_password_policy)
    ApplicationRoute.objects.create(application=dashboard, display_name='Admin', path_prefix='/admin', policy=password_totp_policy, order=0)
    ApplicationRoute.objects.create(application=dashboard, display_name='API', path_prefix='/api', policy=trusted_ips_policy, order=1)

    media = Application.objects.create(display_name='Media', upstream='http://10.0.0.11:32400')
    ApplicationHost.objects.create(application=media, hostname='media.example.test')
    ApplicationHost.objects.create(application=media, hostname='media2.example.test')
    ApplicationPolicy.objects.create(application=media, default_policy=public_policy)

    hypervisor = Application.objects.create(display_name='Hypervisor', upstream='https://10.0.0.12:8006', allow_invalid_cert=True)
    ApplicationHost.objects.create(application=hypervisor, hostname='hypervisor.example.test')
    ApplicationPolicy.objects.create(application=hypervisor, default_policy=trusted_ips_policy)

    files = Application.objects.create(display_name='Files', upstream='http://10.0.0.13:8080')
    ApplicationPolicy.objects.create(application=files, default_policy=totp_only_policy)

    Application.objects.create(display_name='Café', upstream='http://10.0.0.14:8000')

    sso = Application.objects.create(display_name='SSO', upstream='http://10.0.0.15:8000')
    ApplicationHost.objects.create(application=sso, hostname='sso.example.test')
    ApplicationPolicy.objects.create(application=sso, default_policy=oidc_company_policy)


def export_auth_gateway_fixtures(output_dir):
    export_caddy_config(output_dir)

    fixture_environment = {'SERVER_ADDRESS': 'webadmin.example.test', 'EXTRA_ALLOWED_HOSTS': 'webadmin2.example.test,10.0.0.1'}
    with patch.dict(os.environ, fixture_environment), contextlib.redirect_stdout(io.StringIO()):
        webadmin_config = _WEBADMIN_EXPORT_MODULE.build_config(_WEBADMIN_EXPORT_MODULE.collect_hosts())
        _WEBADMIN_EXPORT_MODULE._write_config(os.path.join(output_dir, 'wireguard_webadmin.json'), webadmin_config)


class AuthGatewayFixturesTests(TestCase):
    maxDiff = None

    def setUp(self):
        create_auth_gateway_scenario()

    def test_auth_gateway_fixtures_match_exporter(self):
        if os.environ.get(UPDATE_FIXTURES_ENV) == '1':
            export_auth_gateway_fixtures(AUTH_GATEWAY_FIXTURES_DIR)
            return

        with tempfile.TemporaryDirectory() as output_dir:
            export_auth_gateway_fixtures(output_dir)
            generated_files = sorted(path.name for path in Path(output_dir).glob('*.json'))
            fixture_files = sorted(path.name for path in AUTH_GATEWAY_FIXTURES_DIR.glob('*.json'))
            self.assertEqual(generated_files, fixture_files)

            for filename in generated_files:
                generated_data = json.loads((Path(output_dir) / filename).read_text(encoding='utf-8'))
                fixture_data = json.loads((AUTH_GATEWAY_FIXTURES_DIR / filename).read_text(encoding='utf-8'))
                self.assertEqual(
                    generated_data, fixture_data,
                    f"{filename} is out of date. Regenerate it with: "
                    f"{UPDATE_FIXTURES_ENV}=1 python manage.py test app_gateway"
                )
