import sys

from django.conf import settings
from django.core.management.base import BaseCommand, CommandError
from django.db import transaction
from django.db.models import F

from app_gateway.caddy_config_export import apply_caddy_config
from app_gateway.models import Application, ApplicationHost, RESERVED_APP_NAME
from app_gateway.setup_defaults import create_default_entries

CERTIFICATE_OPTIONS = (
    ('http_challenge', 'HTTP validation (default)'),
    ('self_signed', 'Self-signed'),
)


class Command(BaseCommand):
    help = 'Interactively reset the certificate settings of the WireGuard WebAdmin hosts'

    def handle(self, *args, **options):
        if not sys.stdin.isatty():
            raise CommandError(
                'This command must be run interactively. '
                'Use: docker exec -it wireguard-webadmin python manage.py reset_webadmin_certificate'
            )

        create_default_entries()

        application = Application.objects.filter(name=RESERVED_APP_NAME).first()
        if not application:
            raise CommandError(f'Application "{RESERVED_APP_NAME}" not found.')

        hosts = list(application.hosts.select_related('dns_credential').order_by('hostname'))
        if not hosts:
            raise CommandError('WireGuard WebAdmin has no hosts. Check SERVER_ADDRESS and EXTRA_ALLOWED_HOSTS.')

        self.stdout.write('\nWireGuard WebAdmin hosts:')
        for index, host in enumerate(hosts, start=1):
            credential = f', credential: {host.dns_credential}' if host.dns_credential else ''
            self.stdout.write(f'  [{index}] {host.hostname} ({host.certificate_label}{credential})')
        selected_hosts = self.ask_hosts(hosts)

        self.stdout.write('\nNew certificate:')
        for index, (certificate_type, label) in enumerate(CERTIFICATE_OPTIONS, start=1):
            self.stdout.write(f'  [{index}] {label}')
        certificate_type, certificate_label = self.ask_certificate_type()

        self.stdout.write('\nThe following changes will be applied:')
        for host in selected_hosts:
            self.stdout.write(f'  {host.hostname}: {host.certificate_label} -> {certificate_label}')
        self.stdout.write(
            'The DNS credential is removed from these hosts and a new certificate is issued right away. '
            'Until it is issued, the hosts are served with a self-signed certificate.'
        )

        if self.ask('\nType "yes" to continue, or anything else to cancel: ').lower() != 'yes':
            self.stdout.write('Operation cancelled. No changes were made.')
            return

        with transaction.atomic():
            ApplicationHost.objects.filter(pk__in=[host.pk for host in selected_hosts]).update(
                certificate_type=certificate_type,
                dns_credential=None,
                certificate_fallback=True,
                certificate_generation=F('certificate_generation') + 1,
            )
        self.stdout.write(self.style.SUCCESS('Changes applied.'))

        if settings.CADDY_ENABLED:
            self.stdout.write('Exporting Caddy configuration...')
            apply_caddy_config()
            self.stdout.write(self.style.SUCCESS('Caddy configuration exported.'))
        else:
            self.stdout.write('Skipping Caddy configuration export (CADDY_ENABLED is not set).')

    def ask(self, prompt):
        try:
            return input(prompt).strip()
        except (EOFError, KeyboardInterrupt):
            raise CommandError('\nOperation cancelled. No changes were made.')

    def ask_hosts(self, hosts):
        while True:
            answer = self.ask("Hosts to reset (comma separated numbers, or empty for all): ").lower()
            if not answer or answer == 'all':
                return hosts

            selected_hosts = []
            valid_answer = True
            for item in answer.split(','):
                item = item.strip()
                if not item:
                    continue
                if not item.isdigit() or not 1 <= int(item) <= len(hosts):
                    valid_answer = False
                    break
                host = hosts[int(item) - 1]
                if host not in selected_hosts:
                    selected_hosts.append(host)

            if valid_answer and selected_hosts:
                return selected_hosts
            self.stdout.write(self.style.ERROR(f'Invalid selection: {answer}'))

    def ask_certificate_type(self):
        while True:
            answer = self.ask('Certificate (number, or empty for HTTP validation): ')
            if not answer:
                return CERTIFICATE_OPTIONS[0]
            if answer.isdigit() and 1 <= int(answer) <= len(CERTIFICATE_OPTIONS):
                return CERTIFICATE_OPTIONS[int(answer) - 1]
            self.stdout.write(self.style.ERROR(f'Invalid selection: {answer}'))
