import contextlib
import hashlib
import importlib.util
import io
import json
import os
import tempfile
from pathlib import Path
from unittest.mock import patch

from django.conf import settings
from django.contrib.auth.models import User
from django.contrib.messages import get_messages
from django.test import TestCase, override_settings

from app_gateway.caddy_config_export import build_tls_data, export_caddy_config
from app_gateway.forms import ApplicationForm, ApplicationHostForm, DnsChallengeCredentialForm
from app_gateway.models import (
    AccessPolicy, Application, ApplicationHost, ApplicationPolicy, ApplicationRoute, DnsChallengeCredential
)
from app_gateway.setup_defaults import create_default_entries
from cluster.models import ClusterSettings, Worker
from gatekeeper.models import (
    AuthMethod, AuthMethodAllowedDomain, AuthMethodAllowedEmail, GatekeeperGroup, GatekeeperIPAddress, GatekeeperUser
)
from user_manager.models import UserAcl

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

_PROCESS_CONFIG_PATH = Path(settings.BASE_DIR) / 'containers' / 'caddy' / 'process_config.py'
_PROCESS_CONFIG_SPEC = importlib.util.spec_from_file_location('caddy_process_config', _PROCESS_CONFIG_PATH)
process_config = importlib.util.module_from_spec(_PROCESS_CONFIG_SPEC)
_PROCESS_CONFIG_SPEC.loader.exec_module(process_config)


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


# Same hosts used for wireguard_webadmin.json, so the WireGuard WebAdmin hosts do not depend on the local .env
FIXTURE_ALLOWED_HOSTS = ['wireguard-webadmin', 'webadmin.example.test', 'webadmin2.example.test', '10.0.0.1']


@override_settings(ALLOWED_HOSTS=FIXTURE_ALLOWED_HOSTS)
class AuthGatewayFixturesTests(TestCase):
    maxDiff = None

    def setUp(self):
        create_default_entries()
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


CLOUDFLARE_TOKEN = 'cfut_' + 'a' * 40


def caddy_app(app_id, hosts):
    return {'id': app_id, 'hosts': hosts, 'upstream': 'http://10.0.0.10:8080'}


def site_block(caddyfile, host):
    """Return the lines of the site block that starts with the given host."""
    lines = caddyfile.splitlines()
    start = next(index for index, line in enumerate(lines) if line.startswith(host) and line.endswith('{'))
    end = next(index for index in range(start + 1, len(lines)) if lines[index] == '}')
    return lines[start:end + 1]


class CaddyfileTlsTests(TestCase):
    tls_data = {
        'hosts': {
            'http.example.test': {'certificate_type': 'http_challenge'},
            'strict.example.test': {'certificate_type': 'http_challenge', 'certificate_fallback': False},
            'dns.example.test': {'certificate_type': 'dns_challenge', 'dns_credential': 'cloudflare'},
            'internal.example.test': {'certificate_type': 'self_signed'},
            'worker-only.example.test': {'certificate_type': 'dns_challenge', 'dns_credential': 'cloudflare',
                                         'certificate_only': True, 'export_certificate': True},
        },
        'dns_credentials': {'cloudflare': {'provider': 'cloudflare', 'credentials': {'api_token': CLOUDFLARE_TOKEN}}},
    }

    def build(self, apps, tls_data=None):
        return process_config.build_caddyfile(apps, None, None, tls_data or self.tls_data)

    def test_hosts_are_grouped_by_certificate_settings(self):
        caddyfile = self.build([caddy_app('app', [
            'http.example.test', 'strict.example.test', 'dns.example.test', 'internal.example.test', 'unknown.example.test'
        ])])
        self.assertEqual(
            site_block(caddyfile, 'http.example.test')[:5],
            ['http.example.test, unknown.example.test {', '  tls {', '    issuer acme', '    issuer internal', '  }'],
        )
        self.assertEqual(site_block(caddyfile, 'strict.example.test')[:4], ['strict.example.test {', '  tls {', '    issuer acme', '  }'])
        self.assertEqual(site_block(caddyfile, 'internal.example.test')[1], '  tls internal')

        dns_block = '\n'.join(site_block(caddyfile, 'dns.example.test'))
        self.assertIn(f'api_token "{CLOUDFLARE_TOKEN}"', dns_block)
        self.assertIn('propagation_delay 30s', dns_block)
        self.assertIn('propagation_timeout -1', dns_block)
        self.assertIn('issuer internal', dns_block)

    def test_dns_challenge_can_be_disabled_after_invalid_configuration(self):
        with patch.object(process_config, 'DISABLE_DNS_CHALLENGE', True):
            caddyfile = self.build([caddy_app('app', ['dns.example.test'])])
        self.assertNotIn('dns cloudflare', caddyfile)
        self.assertIn('issuer acme', '\n'.join(site_block(caddyfile, 'dns.example.test')))

    def test_primary_keeps_certificates_of_worker_only_hosts(self):
        caddyfile = self.build([caddy_app('app', ['http.example.test'])])
        worker_only_block = site_block(caddyfile, 'worker-only.example.test')
        self.assertIn('  respond 404', worker_only_block)
        self.assertIn('      dns cloudflare {', worker_only_block)

    def test_cluster_node_never_requests_acme_certificates(self):
        node_tls = {'hosts': {
            'ready.example.test': {'certificate_type': 'dns_challenge', 'certificate_file': 'a' * 64},
            'waiting.example.test': {'certificate_type': 'dns_challenge', 'certificate_file': ''},
            'strict.example.test': {'certificate_type': 'dns_challenge', 'certificate_fallback': False, 'certificate_file': ''},
            'internal.example.test': {'certificate_type': 'self_signed'},
        }, 'dns_credentials': {}}
        apps = [caddy_app('app', list(node_tls['hosts']))]
        with patch.object(process_config, 'CLUSTER_NODE', True), \
                patch.object(process_config, 'NODE_CERTIFICATES_DIR', '/caddy_certificates'):
            caddyfile = self.build(apps, node_tls)

        self.assertNotIn('issuer acme', caddyfile)
        self.assertNotIn('strict.example.test', caddyfile)
        certificate_path = '/caddy_certificates/' + 'a' * 64
        self.assertEqual(site_block(caddyfile, 'ready.example.test')[1], f'  tls {certificate_path}.crt {certificate_path}.key')
        self.assertEqual(site_block(caddyfile, 'waiting.example.test')[0], 'waiting.example.test, internal.example.test {')
        self.assertEqual(site_block(caddyfile, 'waiting.example.test')[1], '  tls internal')


class CaddyTlsStateTests(TestCase):
    """Fallback certificates are removed and Caddy is restarted only when the certificate settings change."""

    def setUp(self):
        self.temp_dir = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp_dir.cleanup)
        self.certificates_dir = os.path.join(self.temp_dir.name, 'certificates')
        self.json_dir = os.path.join(self.temp_dir.name, 'json')
        self.export_dir = os.path.join(self.temp_dir.name, 'export')
        for directory in (self.certificates_dir, self.json_dir, self.export_dir):
            os.makedirs(directory)
        for attribute, value in (
            ('CERTIFICATES_DIR', self.certificates_dir),
            ('TLS_STATE_PATH', os.path.join(self.temp_dir.name, 'tls_state.json')),
            ('TLS_STATE_PENDING_PATH', os.path.join(self.temp_dir.name, 'tls_state_pending.json')),
            ('JSON_DIR', self.json_dir),
            ('CERTIFICATE_EXPORT_DIR', self.export_dir),
        ):
            patcher = patch.object(process_config, attribute, value)
            patcher.start()
            self.addCleanup(patcher.stop)

    def store_certificate(self, issuer_dir_name, host, content='certificate'):
        host_dir = os.path.join(self.certificates_dir, issuer_dir_name, host)
        os.makedirs(host_dir, exist_ok=True)
        for extension in ('crt', 'key'):
            with open(os.path.join(host_dir, f'{host}.{extension}'), 'w', encoding='utf-8') as certificate_file:
                certificate_file.write(f'{content}-{extension}')
        return host_dir

    def apply(self, host_tls):
        apps = [caddy_app('app', ['app.example.test'])]
        tls_data = {'hosts': {'app.example.test': host_tls}, 'dns_credentials': {}}
        process_config._write_json(process_config.TLS_STATE_PENDING_PATH, process_config.build_tls_state(apps, tls_data))
        output = io.StringIO()
        with contextlib.redirect_stdout(output), contextlib.redirect_stderr(io.StringIO()):
            process_config.sync_tls_state()
        return output.getvalue().strip() == 'restart'

    def test_first_run_never_restarts(self):
        fallback_dir = self.store_certificate('local', 'app.example.test')
        self.assertFalse(self.apply({'certificate_type': 'http_challenge'}))
        self.assertTrue(os.path.isdir(fallback_dir))

    def test_retry_removes_fallback_certificate(self):
        self.apply({'certificate_type': 'http_challenge'})
        fallback_dir = self.store_certificate('local', 'app.example.test')
        self.assertTrue(self.apply({'certificate_type': 'http_challenge', 'certificate_generation': 1}))
        self.assertFalse(os.path.isdir(fallback_dir))

    def test_retry_keeps_valid_acme_certificate_without_restart(self):
        self.apply({'certificate_type': 'http_challenge'})
        acme_dir = self.store_certificate('acme-v02.api.letsencrypt.org-directory', 'app.example.test')
        self.assertFalse(self.apply({'certificate_type': 'http_challenge', 'certificate_generation': 1}))
        self.assertTrue(os.path.isdir(acme_dir))

    def test_switching_to_self_signed_restarts_when_acme_certificate_is_cached(self):
        self.apply({'certificate_type': 'http_challenge'})
        self.store_certificate('acme-v02.api.letsencrypt.org-directory', 'app.example.test')
        self.assertTrue(self.apply({'certificate_type': 'self_signed'}))

    def test_unchanged_settings_do_not_restart(self):
        self.apply({'certificate_type': 'http_challenge'})
        self.store_certificate('local', 'app.example.test')
        self.assertFalse(self.apply({'certificate_type': 'http_challenge'}))

    def test_readded_host_with_leftover_fallback_is_retried(self):
        self.apply({'certificate_type': 'http_challenge'})
        fallback_dir = self.store_certificate('local', 'other.example.test')
        apps = [caddy_app('app', ['app.example.test', 'other.example.test'])]
        tls_data = {'hosts': {'app.example.test': {'certificate_type': 'http_challenge'},
                              'other.example.test': {'certificate_type': 'dns_challenge', 'dns_credential': 'cloudflare'}},
                    'dns_credentials': {'cloudflare': {'provider': 'cloudflare', 'credentials': {'api_token': CLOUDFLARE_TOKEN}}}}
        process_config._write_json(process_config.TLS_STATE_PENDING_PATH, process_config.build_tls_state(apps, tls_data))
        output = io.StringIO()
        with contextlib.redirect_stdout(output), contextlib.redirect_stderr(io.StringIO()):
            process_config.sync_tls_state()
        self.assertEqual(output.getvalue().strip(), 'restart')
        self.assertFalse(os.path.isdir(fallback_dir))

    def test_new_host_without_cached_certificate_does_not_restart(self):
        self.apply({'certificate_type': 'http_challenge'})
        apps = [caddy_app('app', ['app.example.test', 'new.example.test'])]
        tls_data = {'hosts': {'app.example.test': {'certificate_type': 'http_challenge'},
                              'new.example.test': {'certificate_type': 'http_challenge'}}, 'dns_credentials': {}}
        process_config._write_json(process_config.TLS_STATE_PENDING_PATH, process_config.build_tls_state(apps, tls_data))
        output = io.StringIO()
        with contextlib.redirect_stdout(output), contextlib.redirect_stderr(io.StringIO()):
            process_config.sync_tls_state()
        self.assertEqual(output.getvalue().strip(), '')

    def test_cluster_node_restarts_when_certificate_changes(self):
        with patch.object(process_config, 'CLUSTER_NODE', True):
            self.apply({'certificate_type': 'dns_challenge', 'certificate_file': ''})
            fallback_dir = self.store_certificate('local', 'app.example.test')
            self.assertTrue(self.apply({'certificate_type': 'dns_challenge', 'certificate_file': 'a' * 64}))
            self.assertFalse(os.path.isdir(fallback_dir))
            self.assertTrue(self.apply({'certificate_type': 'dns_challenge', 'certificate_file': 'b' * 64}))

    def test_only_acme_certificates_are_exported(self):
        tls_data = {'hosts': {
            'exported.example.test': {'certificate_type': 'dns_challenge', 'export_certificate': True},
            'fallback.example.test': {'certificate_type': 'dns_challenge', 'export_certificate': True},
            'local.example.test': {'certificate_type': 'dns_challenge'},
        }}
        with open(os.path.join(self.json_dir, 'tls.json'), 'w', encoding='utf-8') as tls_file:
            json.dump(tls_data, tls_file)
        self.store_certificate('acme-v02.api.letsencrypt.org-directory', 'exported.example.test', 'acme')
        self.store_certificate('acme-v02.api.letsencrypt.org-directory', 'local.example.test', 'acme')
        self.store_certificate('local', 'fallback.example.test', 'internal')
        os.makedirs(os.path.join(self.export_dir, 'removed.example.test'))

        with contextlib.redirect_stdout(io.StringIO()):
            process_config.export_certificates()

        self.assertEqual(sorted(os.listdir(self.export_dir)), ['exported.example.test'])
        with open(os.path.join(self.export_dir, 'exported.example.test', 'certificate.crt'), encoding='utf-8') as certificate_file:
            self.assertEqual(certificate_file.read(), 'acme-crt')


@override_settings(ALLOWED_HOSTS=FIXTURE_ALLOWED_HOSTS)
class ClusterApplicationFormTests(TestCase):
    def setUp(self):
        ClusterSettings.objects.update_or_create(name='cluster_settings', defaults={'enabled': True})
        self.worker = Worker.objects.create(name='node-a')
        self.application = Application.objects.create(display_name='Wiki', upstream='http://10.0.0.30:8080')
        self.credential = DnsChallengeCredential.objects.create(
            display_name='Cloudflare', provider='cloudflare', credentials={'api_token': CLOUDFLARE_TOKEN}
        )

    def test_application_with_http_validation_hosts_cannot_be_served_by_workers(self):
        ApplicationHost.objects.create(application=self.application, hostname='wiki.example.test')
        form = ApplicationForm(data={
            'display_name': 'Wiki', 'upstream': 'http://10.0.0.30:8080', 'serve_on_primary': 'on',
            'workers': [self.worker.pk],
        }, instance=self.application)
        self.assertFalse(form.is_valid())
        self.assertIn('wiki.example.test', str(form.errors))

    def test_all_workers_and_specific_workers_are_exclusive(self):
        form = ApplicationForm(data={
            'display_name': 'Wiki', 'upstream': 'http://10.0.0.30:8080', 'serve_on_primary': 'on',
            'all_workers': 'on', 'workers': [self.worker.pk],
        }, instance=self.application)
        self.assertIn('workers', form.errors)

    def test_application_must_be_published_somewhere(self):
        form = ApplicationForm(data={'display_name': 'Wiki', 'upstream': 'http://10.0.0.30:8080'}, instance=self.application)
        self.assertFalse(form.is_valid())
        self.assertIn('__all__', form.errors)

    def test_without_cluster_everything_is_served_by_the_primary(self):
        self.application.serve_on_primary = False
        self.application.save()
        self.application.workers.add(self.worker)
        ClusterSettings.objects.filter(name='cluster_settings').update(enabled=False)
        self.assertTrue(self.application.is_served_by(None))
        self.assertFalse(self.application.is_served_by(self.worker))
        self.assertFalse(self.application.served_by_workers)
        form = ApplicationForm(data={'display_name': 'Wiki', 'upstream': 'http://10.0.0.30:8080'}, instance=self.application)
        self.assertTrue(form.is_valid(), form.errors)
        self.assertNotIn('workers', form.fields)

    def test_host_of_application_served_by_workers_requires_dns_or_self_signed(self):
        self.application.workers.add(self.worker)
        form = ApplicationHostForm(
            data={'hostname': 'wiki.example.test', 'certificate_type': 'http_challenge', 'certificate_fallback': 'on'},
            application=self.application,
        )
        self.assertIn('certificate_type', form.errors)
        form = ApplicationHostForm(data={
            'hostname': 'wiki.example.test', 'certificate_type': 'dns_challenge',
            'dns_credential': self.credential.pk, 'certificate_fallback': 'on',
        }, application=self.application)
        self.assertTrue(form.is_valid(), form.errors)


@override_settings(ALLOWED_HOSTS=FIXTURE_ALLOWED_HOSTS + ['testserver'], CADDY_ENABLED=True, DEBUG=False)
class GatewayAutoApplyTests(TestCase):
    def setUp(self):
        self.temp_dir = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp_dir.cleanup)
        patcher = patch('app_gateway.caddy_config_export.CADDY_EXPORT_DIR', self.temp_dir.name)
        patcher.start()
        self.addCleanup(patcher.stop)
        user = User.objects.create_user(username='gateway-admin', password='unused-test-password')
        UserAcl.objects.create(user=user, user_level=50)
        self.client.force_login(user)

    def save_application(self):
        return self.client.post('/app_gateway/application/manage/', {
            'display_name': 'Auto Apply', 'upstream': 'http://10.0.0.40:8080',
        })

    @override_settings(AUTO_APPLY=True)
    def test_saving_applies_configuration(self):
        self.save_application()
        with open(os.path.join(self.temp_dir.name, 'applications.json'), encoding='utf-8') as applications_file:
            self.assertIn('auto-apply', [entry['id'] for entry in json.load(applications_file)['entries']])

    @override_settings(AUTO_APPLY=False)
    def test_disabled_auto_apply_keeps_changes_pending(self):
        self.save_application()
        self.assertFalse(os.path.exists(os.path.join(self.temp_dir.name, 'applications.json')))


DELEGATION_DOMAIN = 'acme.example.net'
# Long enough for its challenge record in the delegation domain to exceed the 253 characters of a DNS name
LONG_HOSTNAME = '.'.join(['a' * 63, 'b' * 63, 'c' * 63, 'd' * 45, 'test'])


class DnsDelegationTestMixin:
    def setUp(self):
        super().setUp()
        self.application = Application.objects.create(display_name='Wiki', upstream='http://10.0.0.30:8080')
        self.credential = DnsChallengeCredential.objects.create(
            display_name='Delegated', provider='cloudflare', credentials={'api_token': CLOUDFLARE_TOKEN},
            delegation_domain=DELEGATION_DOMAIN,
        )

    def add_host(self, hostname, certificate_type='dns_challenge', credential=None):
        return ApplicationHost.objects.create(
            application=self.application, hostname=hostname, certificate_type=certificate_type,
            dns_credential=(credential or self.credential) if certificate_type == 'dns_challenge' else None,
        )


class DnsDelegationModelTests(DnsDelegationTestMixin, TestCase):
    def test_challenge_record_is_the_hostname_inside_the_delegation_domain(self):
        self.assertEqual(self.credential.delegation_target('App.Example.com.'), 'app.example.com.acme.example.net')
        self.assertEqual(self.credential.delegation_target('*.example.com'), 'example.com.acme.example.net')

    def test_hostnames_inside_the_delegation_domain_are_validated_directly(self):
        self.assertIsNone(self.credential.delegation_target('acme.example.net'))
        self.assertIsNone(self.credential.delegation_target('app.acme.example.net'))
        self.assertEqual(self.credential.delegation_target('app.example.net'), 'app.example.net.acme.example.net')

    def test_credential_without_delegation_domain_is_not_delegated(self):
        self.credential.delegation_domain = ''
        self.assertIsNone(self.credential.delegation_target('app.example.com'))

    def test_host_record_and_certificate_label(self):
        delegated = self.add_host('app.example.com')
        self.assertEqual(
            delegated.dns_delegation_record, ('_acme-challenge.app.example.com', 'app.example.com.acme.example.net')
        )
        self.assertEqual(delegated.certificate_label, 'DNS validation (delegated)')

        direct = self.add_host('app.acme.example.net')
        self.assertIsNone(direct.dns_delegation_record)
        self.assertEqual(direct.certificate_label, 'DNS validation')

        http_host = self.add_host('http.example.com', certificate_type='http_challenge')
        self.assertIsNone(http_host.dns_delegation_record)
        self.assertEqual(http_host.certificate_label, 'HTTP validation')


class DnsDelegationExportTests(DnsDelegationTestMixin, TestCase):
    def test_only_delegated_hosts_export_the_override_domain(self):
        self.add_host('app.example.com')
        self.add_host('app.acme.example.net')
        hosts = build_tls_data()['hosts']
        self.assertEqual(hosts['app.example.com']['dns_challenge_override_domain'], 'app.example.com.acme.example.net')
        self.assertNotIn('dns_challenge_override_domain', hosts['app.acme.example.net'])


class DnsDelegationCaddyfileTests(TestCase):
    credential = {'provider': 'cloudflare', 'credentials': {'api_token': CLOUDFLARE_TOKEN}}

    def tls_data(self, overrides):
        hosts = {}
        for host, override_domain in overrides.items():
            hosts[host] = {'certificate_type': 'dns_challenge', 'dns_credential': 'cloudflare'}
            if override_domain is not None:
                hosts[host]['dns_challenge_override_domain'] = override_domain
        return {'hosts': hosts, 'dns_credentials': {'cloudflare': self.credential}}

    def build(self, overrides):
        apps = [caddy_app('app', list(overrides))]
        return process_config.build_caddyfile(apps, None, None, self.tls_data(overrides))

    def test_each_delegated_host_gets_its_own_override_domain(self):
        caddyfile = self.build({
            'a.example.com': 'a.example.com.acme.example.net',
            'b.example.com': 'b.example.com.acme.example.net',
            'c.example.com': None,
            'd.example.com': None,
        })
        a_block = site_block(caddyfile, 'a.example.com')
        self.assertEqual(a_block[0], 'a.example.com {')
        self.assertIn('      dns_challenge_override_domain a.example.com.acme.example.net', a_block)
        self.assertIn('      dns_challenge_override_domain b.example.com.acme.example.net', site_block(caddyfile, 'b.example.com'))

        direct_block = site_block(caddyfile, 'c.example.com')
        self.assertEqual(direct_block[0], 'c.example.com, d.example.com {')
        self.assertNotIn('dns_challenge_override_domain', '\n'.join(direct_block))

    def test_invalid_override_domain_is_not_written(self):
        caddyfile = self.build({'a.example.com': 'bad"} name', 'b.example.com': None})
        self.assertNotIn('dns_challenge_override_domain', caddyfile)
        self.assertEqual(site_block(caddyfile, 'a.example.com')[0], 'a.example.com, b.example.com {')

    def test_tls_state_of_hosts_without_delegation_is_unchanged(self):
        apps = [caddy_app('app', ['a.example.com', 'b.example.com'])]
        tls_state = process_config.build_tls_state(
            apps, self.tls_data({'a.example.com': None, 'b.example.com': 'b.example.com.acme.example.net'})
        )
        credential_hash = hashlib.sha256(json.dumps(self.credential, sort_keys=True).encode()).hexdigest()
        self.assertEqual(tls_state['a.example.com'][2], credential_hash)
        self.assertNotEqual(tls_state['b.example.com'][2], credential_hash)


class DnsDelegationFormTests(DnsDelegationTestMixin, TestCase):
    def credential_form(self, delegation_domain, instance=None):
        return DnsChallengeCredentialForm(data={
            'display_name': 'Delegated', 'provider': 'cloudflare', 'delegation_domain': delegation_domain,
        }, instance=instance or self.credential)

    def test_delegation_domain_is_normalized(self):
        form = self.credential_form('Acme.Example.NET.')
        self.assertTrue(form.is_valid(), form.errors)
        self.assertEqual(form.cleaned_data['delegation_domain'], 'acme.example.net')

    def test_invalid_delegation_domain_is_rejected(self):
        for value in ('bad domain', 'nodot', '-x.example.net', 'x.example.net/path'):
            self.assertIn('delegation_domain', self.credential_form(value).errors, value)

    def test_delegation_domain_too_long_for_existing_hosts_is_rejected(self):
        self.credential.delegation_domain = ''
        self.credential.save()
        self.add_host(LONG_HOSTNAME)
        self.assertIn(LONG_HOSTNAME, str(self.credential_form(DELEGATION_DOMAIN).errors['delegation_domain']))

    def test_host_whose_challenge_record_is_too_long_is_rejected(self):
        form = ApplicationHostForm(data={
            'hostname': LONG_HOSTNAME, 'certificate_type': 'dns_challenge', 'dns_credential': self.credential.pk,
            'certificate_fallback': 'on',
        }, application=self.application)
        self.assertIn('dns_credential', form.errors)


@override_settings(ALLOWED_HOSTS=FIXTURE_ALLOWED_HOSTS + ['testserver'], CADDY_ENABLED=True, AUTO_APPLY=False)
class DnsDelegationViewTests(DnsDelegationTestMixin, TestCase):
    def setUp(self):
        super().setUp()
        user = User.objects.create_user(username='gateway-admin', password='unused-test-password')
        UserAcl.objects.create(user=user, user_level=50)
        self.client.force_login(user)

    def test_host_form_knows_the_delegated_credentials_and_current_record(self):
        DnsChallengeCredential.objects.create(
            display_name='Direct', provider='cloudflare', credentials={'api_token': CLOUDFLARE_TOKEN}
        )
        host = self.add_host('app.example.com')
        response = self.client.get(f'/app_gateway/host/manage/?uuid={host.uuid}')
        self.assertEqual(response.context['delegation_domains'], {str(self.credential.pk): DELEGATION_DOMAIN})
        self.assertEqual(
            response.context['initial_delegation_record'],
            '_acme-challenge.app.example.com app.example.com.acme.example.net',
        )

    def test_changing_the_delegation_domain_warns_about_existing_hosts(self):
        self.add_host('app.example.com')
        response = self.client.post(f'/app_gateway/dns_credential/manage/?uuid={self.credential.uuid}', {
            'display_name': 'Delegated', 'provider': 'cloudflare', 'delegation_domain': 'other.example.net',
        })
        self.credential.refresh_from_db()
        self.assertEqual(self.credential.delegation_domain, 'other.example.net')
        self.assertEqual(self.credential.credentials, {'api_token': CLOUDFLARE_TOKEN})
        warnings = [message.message for message in get_messages(response.wsgi_request) if message.level_tag == 'warning']
        self.assertEqual(len(warnings), 1)
        self.assertIn('1 hosts', warnings[0])
