import uuid

from django.db import models


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


class DNSFilterList(models.Model):
    name = models.SlugField(max_length=100, unique=True)
    description = models.CharField(max_length=100)
    enabled = models.BooleanField(default=False)
    list_url = models.URLField()
    last_updated = models.DateTimeField(blank=True, null=True)
    host_count = models.IntegerField(default=0)

    created = models.DateTimeField(auto_now_add=True)
    updated = models.DateTimeField(auto_now=True)
    uuid = models.UUIDField(unique=True, default=uuid.uuid4, editable=False)

    def __str__(self):
        return self.name