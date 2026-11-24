from django.core.management.base import BaseCommand, CommandError

from cluster.models import ClusterSettings


class Command(BaseCommand):
    help = 'Exit with status 1 when WireGuard is disabled on the primary server in the cluster settings'

    def handle(self, *args, **options):
        if not ClusterSettings.primary_serves_clients():
            raise CommandError('WireGuard is disabled on the primary server in the cluster settings', returncode=1)
