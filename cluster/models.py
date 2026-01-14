import uuid

from django.db import models
from django.utils.translation import gettext_lazy as _


class ClusterSettings(models.Model):
    name = models.CharField(default='cluster_settings', max_length=16, unique=True)
    enabled = models.BooleanField(default=False)
    primary_enable_wireguard = models.BooleanField(default=True)
    cluster_mode = models.CharField(default='mirror', max_length=16, choices=(('mirror', 'Mirror'), ))
    restart_mode = models.CharField(default='auto', max_length=16, choices=(('auto', 'Automatic restart'),))
    worker_display = models.CharField(
        default='server_address', max_length=16, choices=(
            ('name', 'Name'), ('server_address', 'Server Address'),
            ('location', 'Location'), ('address_location', 'Address + Location')
        )
    )
    config_version = models.PositiveIntegerField(default=0)
    dns_version = models.PositiveIntegerField(default=0)

    updated = models.DateTimeField(auto_now=True)
    created = models.DateTimeField(auto_now_add=True)
    uuid = models.UUIDField(default=uuid.uuid4, editable=False, unique=True)

    def __str__(self):
        return self.name


class Worker(models.Model):
    name = models.CharField(max_length=100, unique=True)
    enabled = models.BooleanField(default=True)
    token = models.UUIDField(default=uuid.uuid4, unique=True)
    ip_lock = models.BooleanField(default=False)
    ip_address = models.GenericIPAddressField(blank=True, null=True)

    force_reload = models.BooleanField(default=False)
    force_restart = models.BooleanField(default=False)

    country = models.CharField(max_length=100, blank=True, null=True)
    city = models.CharField(max_length=100, blank=True, null=True)
    hostname = models.CharField(max_length=100, blank=True, null=True)

    error_status = models.CharField(default='', max_length=32, choices=(
        ('', ''),
        ('ip_lock', _('IP lock is enabled, but the worker is attempting to access from a different IP address.')),
        ('worker_disabled', _('Worker is not enabled')),
        ('cluster_disabled', _('Cluster is not enabled')),
        ('missing_version', _('Please report worker_config_version, worker_dns_version and worker_version in the API request.')),
        ('update_required', _('Worker update is required.'))
    ))

    updated = models.DateTimeField(auto_now=True)
    created = models.DateTimeField(auto_now_add=True)
    uuid = models.UUIDField(default=uuid.uuid4, editable=False, unique=True)

    def __str__(self):
        return self.name

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
    last_reload = models.DateTimeField(blank=True, null=True)
    last_restart = models.DateTimeField(blank=True, null=True)
    dns_version = models.PositiveIntegerField(default=0)
    config_version = models.PositiveIntegerField(default=0)
    worker_version = models.PositiveIntegerField(default=0)
    active_peers = models.PositiveIntegerField(default=0)
    wireguard_status = models.JSONField(blank=True, null=True)
    wireguard_status_updated = models.DateTimeField(blank=True, null=True)

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
