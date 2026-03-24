import os

from django.conf import settings
from django.core.management.base import BaseCommand

from wireguard_tools.views import export_firewall_configuration, export_wireguard_configuration


class Command(BaseCommand):
    help = 'Export WireGuard, firewall and Caddy configuration files'

    def handle(self, *args, **options):
        self.stdout.write('Exporting WireGuard configuration...')
        export_wireguard_configuration()
        self.stdout.write(self.style.SUCCESS('WireGuard configuration exported.'))

        self.stdout.write('Exporting firewall configuration...')
        export_firewall_configuration()
        self.stdout.write(self.style.SUCCESS('Firewall configuration exported.'))

        if settings.CADDY_ENABLED:
            self.stdout.write('Exporting Caddy configuration...')
            try:
                from app_gateway.caddy_config_export import export_caddy_config
                export_caddy_config('/caddy_json_export/')
                if settings.DEBUG:
                    export_caddy_config(os.path.join(settings.BASE_DIR, 'containers', 'caddy', 'config_files'))
                self.stdout.write(self.style.SUCCESS('Caddy configuration exported.'))
            except Exception as e:
                self.stdout.write(self.style.WARNING(f'Failed to export Caddy configuration: {e}'))
        else:
            self.stdout.write('Skipping Caddy configuration export (CADDY_ENABLED is not set).')
