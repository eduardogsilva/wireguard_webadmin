from django.db import models
import uuid


class DNSSettings(models.Model):
    name = models.CharField(default='dns_settings', max_length=100)
    dns_primary = models.GenericIPAddressField(blank=True, null=True, default='1.1.1.1')
    dns_secondary = models.GenericIPAddressField(blank=True, null=True, default='1.0.0.1')
    pending_changes = models.BooleanField(default=True)

    created = models.DateTimeField(auto_now_add=True)
    updated = models.DateTimeField(auto_now=True)
    uuid = models.UUIDField(unique=True, default=uuid.uuid4, editable=False)


class StaticHost(models.Model):
    hostname = models.CharField(max_length=100, unique=True)
    ip_address = models.GenericIPAddressField()

    created = models.DateTimeField(auto_now_add=True)
    updated = models.DateTimeField(auto_now=True)
    uuid = models.UUIDField(unique=True, default=uuid.uuid4, editable=False)

    def __str__(self):
        return self.hostname
