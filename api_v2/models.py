import uuid

from django.db import models

from wireguard.models import WireGuardInstance


class ApiKey(models.Model):
    name = models.CharField(max_length=64, unique=True)
    token = models.UUIDField(default=uuid.uuid4, unique=True)
    allowed_instances = models.ManyToManyField(WireGuardInstance, blank=True, related_name='api_keys')
    allow_restart = models.BooleanField(default=True)
    allow_reload = models.BooleanField(default=True)
    allow_export = models.BooleanField(default=True)
    enabled = models.BooleanField(default=True)

    uuid = models.UUIDField(default=uuid.uuid4, editable=False, unique=True)
    created = models.DateTimeField(auto_now_add=True)
    updated = models.DateTimeField(auto_now=True)
    def __str__(self):
        return self.name