import uuid

from django.db import models
from django.utils.translation import gettext_lazy as _

DISTRIBUTED_MODES = ('distributed',)


class ClusterSettings(models.Model):
    name = models.CharField(default='cluster_settings', max_length=16, unique=True)
    enabled = models.BooleanField(default=False)
    primary_enable_wireguard = models.BooleanField(default=True)
    cluster_mode = models.CharField(
        default='mirror', max_length=16, choices=(('mirror', 'Mirror'), ('distributed', 'Distributed'))
    )
    worker_display = models.CharField(
        default='server_address', max_length=16, choices=(
            ('name', 'Name'), ('server_address', 'Server Address'),
            ('location', 'Location'), ('address_location', 'Address + Location')
        )
    )

    updated = models.DateTimeField(auto_now=True)
    created = models.DateTimeField(auto_now_add=True)
    uuid = models.UUIDField(default=uuid.uuid4, editable=False, unique=True)

    def __str__(self):
        return self.name

    @classmethod
    def cluster_enabled(cls):
        return cls.objects.filter(name='cluster_settings', enabled=True).exists()

    @classmethod
    def is_distributed(cls):
        """Each WireGuard instance runs on a single server. Only applies while the cluster is enabled."""
        return cls.objects.filter(name='cluster_settings', enabled=True, cluster_mode__in=DISTRIBUTED_MODES).exists()


class Worker(models.Model):
    name = models.CharField(max_length=100, unique=True)
    enabled = models.BooleanField(default=True)
    token = models.UUIDField(default=uuid.uuid4, unique=True)
    ip_lock = models.BooleanField(default=False)
    ip_address = models.GenericIPAddressField(blank=True, null=True)

    country = models.CharField(max_length=100, blank=True, null=True)
    city = models.CharField(max_length=100, blank=True, null=True)
    hostname = models.CharField(max_length=100, blank=True, null=True)

    error_status = models.CharField(default='', max_length=32, choices=(
        ('', ''),
        ('ip_lock', _('IP lock is enabled, but the worker is attempting to access from a different IP address.')),
        ('worker_disabled', _('Worker is not enabled')),
        ('cluster_disabled', _('Cluster is not enabled')),
        ('update_required', _('Worker update is required.'))
    ))

    updated = models.DateTimeField(auto_now=True)
    created = models.DateTimeField(auto_now_add=True)
    uuid = models.UUIDField(default=uuid.uuid4, editable=False, unique=True)

    def __str__(self):
        return self.name

    @property
    def server_address(self):
        return self.hostname or self.ip_address or ''

    @property
    def display_name(self):
        cluster_settings = ClusterSettings.objects.first()
        if not cluster_settings:
            return self.name

        mode = cluster_settings.worker_display

        hostname = self.hostname or ''
        ip_address = self.ip_address or ''
        city = self.city or ''
        country = self.country or ''

        location_parts = [part for part in (city, country) if part]
        location = ', '.join(location_parts)

        if mode == 'name':
            return self.name

        if mode == 'server_address':
            return hostname or ip_address or self.name

        if mode == 'location':
            return location or self.name

        if mode == 'address_location':
            address = hostname or ip_address
            if address and location:
                return f"{address} ({location})"
            return address or location or self.name

        return self.name

    @property
    def is_online(self):
        try:
            return self.workerstatus.is_online
        except WorkerStatus.DoesNotExist:
            return False


class WorkerStatus(models.Model):
    worker = models.OneToOneField(Worker, on_delete=models.CASCADE)
    last_seen = models.DateTimeField(auto_now=True)
    worker_version = models.PositiveIntegerField(default=0)
    wireguard_status = models.JSONField(blank=True, null=True)
    wireguard_status_updated = models.DateTimeField(blank=True, null=True)
    # {section: {"hash": ..., "status": "ok"|"error", "message": ..., "updated": ...}}
    section_status = models.JSONField(default=dict, blank=True)
    services_status = models.JSONField(default=dict, blank=True)
    # {hostname: {"status": ..., "issuer": ..., "not_after": ..., "generation": ...}}
    certificate_status = models.JSONField(default=dict, blank=True)
    certificate_status_updated = models.DateTimeField(blank=True, null=True)

    updated = models.DateTimeField(auto_now=True)
    created = models.DateTimeField(auto_now_add=True)
    uuid = models.UUIDField(default=uuid.uuid4, editable=False, unique=True)

    @property
    def is_online(self):
        from django.utils import timezone
        from datetime import timedelta
        if not self.last_seen:
            return False
        return self.last_seen >= timezone.now() - timedelta(minutes=10)
