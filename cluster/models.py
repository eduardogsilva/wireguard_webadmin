import uuid

from django.db import models


class ClusterSettings(models.Model):
    name = models.CharField(default='cluster_settings', max_length=16, unique=True)
    enabled = models.BooleanField(default=False)
    primary_enable_wireguard = models.BooleanField(default=True)
    stats_sync_interval = models.IntegerField(default=60)
    stats_cache_interval = models.IntegerField(default=60)
    cluster_mode = models.CharField(default='mirror', max_length=16, choices=(('mirror', 'Mirror'), ))
    restart_mode = models.CharField(default='auto', max_length=16, choices=(('auto', 'Automatically restart/reload'), ('manual', 'Manual')))
    worker_display = models.CharField(
        default='server_address', max_length=16, choices=(
            ('name', 'Name'), ('server_address', 'Server Address'),
            ('location', 'Location'), ('address_location', 'Address + Location')
        )
    )
    config_version = models.PositiveIntegerField(default=0)

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

    updated = models.DateTimeField(auto_now=True)
    created = models.DateTimeField(auto_now_add=True)
    uuid = models.UUIDField(default=uuid.uuid4, editable=False, unique=True)


class WorkerStatus(models.Model):
    worker = models.OneToOneField(Worker, on_delete=models.CASCADE)
    last_seen = models.DateTimeField(auto_now=True)
    last_reload = models.DateTimeField(blank=True, null=True)
    last_restart = models.DateTimeField(blank=True, null=True)
    config_version = models.PositiveIntegerField(default=0)
    config_pending = models.BooleanField(default=False)
    active_peers = models.PositiveIntegerField(default=0)
    wireguard_status = models.JSONField(default=dict)

    updated = models.DateTimeField(auto_now=True)
    created = models.DateTimeField(auto_now_add=True)
    uuid = models.UUIDField(default=uuid.uuid4, editable=False, unique=True)
