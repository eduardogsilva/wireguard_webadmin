import os
import sys

from django.conf import settings
from django.core.management.base import BaseCommand, CommandError
from django.db import transaction

from app_gateway.caddy_config_export import export_caddy_config
from app_gateway.models import AccessPolicy, Application, ApplicationPolicy, RESERVED_APP_NAME
from app_gateway.setup_defaults import create_default_entries


class Command(BaseCommand):
    help = 'Interactively set the WireGuard WebAdmin application to a public policy, removing auth-gateway authentication'

    def handle(self, *args, **options):
        if not sys.stdin.isatty():
            raise CommandError(
                'This command must be run interactively. '
                'Use: docker exec -it wireguard-webadmin python manage.py disable_webadmin_gateway_auth'
            )

        create_default_entries()

        public_policy = AccessPolicy.objects.filter(policy_type='public').order_by('created').first()
        if not public_policy:
            raise CommandError('No public access policy found.')

        application = Application.objects.filter(name=RESERVED_APP_NAME).first()
        if not application:
            raise CommandError(f'Application "{RESERVED_APP_NAME}" not found.')

        application_policy = ApplicationPolicy.objects.filter(application=application).select_related('default_policy').first()
        current_policy = application_policy.default_policy if application_policy else None
        change_default_policy = not current_policy or current_policy.id != public_policy.id

        protected_routes = list(
            application.routes.exclude(policy__policy_type='public').select_related('policy').order_by('order', 'path_prefix')
        )

        if not change_default_policy and not protected_routes:
            self.stdout.write('WireGuard WebAdmin is already using a public policy. Nothing to do.')
            return

        self.stdout.write(self.style.WARNING(
            '\nWARNING: this command removes the auth-gateway authentication from WireGuard WebAdmin.\n'
            'The web interface will be reachable by anyone who can access this host, protected only by the Django login.\n'
            'Use it only to recover access, and restore the application policy from the web interface right after.\n'
        ))

        if change_default_policy:
            self.stdout.write(f'Default policy: {current_policy} -> {public_policy}')
        else:
            self.stdout.write(f'Default policy is already public: {public_policy}')

        selected_routes = []
        if protected_routes:
            self.stdout.write('\nProtected routes:')
            for index, route in enumerate(protected_routes, start=1):
                self.stdout.write(f'  [{index}] {route.path_prefix} ({route.policy})')
            selected_routes = self.ask_routes(protected_routes)

        if not change_default_policy and not selected_routes:
            self.stdout.write('No changes selected. Nothing to do.')
            return

        self.stdout.write('\nThe following changes will be applied:')
        if change_default_policy:
            self.stdout.write(f'  Default policy: {current_policy} -> {public_policy}')
        for route in selected_routes:
            self.stdout.write(f'  Route {route.path_prefix}: {route.policy} -> {public_policy}')

        if self.ask('\nType "yes" to continue, or anything else to cancel: ').lower() != 'yes':
            self.stdout.write('Operation cancelled. No changes were made.')
            return

        with transaction.atomic():
            if change_default_policy:
                ApplicationPolicy.objects.update_or_create(
                    application=application, defaults={'default_policy': public_policy}
                )
            for route in selected_routes:
                route.policy = public_policy
                route.save()
        self.stdout.write(self.style.SUCCESS('Changes applied.'))

        if settings.CADDY_ENABLED:
            self.stdout.write('Exporting Caddy configuration...')
            export_caddy_config('/caddy_json_export/')
            if settings.DEBUG:
                export_caddy_config(os.path.join(settings.BASE_DIR, 'containers', 'caddy', 'config_files'))
            self.stdout.write(self.style.SUCCESS('Caddy configuration exported.'))
        else:
            self.stdout.write('Skipping Caddy configuration export (CADDY_ENABLED is not set).')

        self.stdout.write(self.style.WARNING(
            'Remember to restore the WireGuard WebAdmin application policy from the web interface once access is recovered.'
        ))

    def ask(self, prompt):
        try:
            return input(prompt).strip()
        except (EOFError, KeyboardInterrupt):
            raise CommandError('\nOperation cancelled. No changes were made.')

    def ask_routes(self, protected_routes):
        while True:
            answer = self.ask("Routes to set as public (comma separated numbers, 'all', or empty for none): ").lower()
            if not answer:
                return []
            if answer == 'all':
                return protected_routes

            selected_routes = []
            valid_answer = True
            for item in answer.split(','):
                item = item.strip()
                if not item:
                    continue
                if not item.isdigit() or not 1 <= int(item) <= len(protected_routes):
                    valid_answer = False
                    break
                route = protected_routes[int(item) - 1]
                if route not in selected_routes:
                    selected_routes.append(route)

            if valid_answer and selected_routes:
                return selected_routes
            self.stdout.write(self.style.ERROR(f'Invalid selection: {answer}'))
