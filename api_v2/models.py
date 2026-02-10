import uuid

from django.db import models
from django.utils.translation import gettext_lazy as _

from wireguard.models import WireGuardInstance


class ApiKey(models.Model):
    name = models.CharField(max_length=64, unique=True, verbose_name=_("Name"))
    token = models.UUIDField(default=uuid.uuid4, unique=True, verbose_name=_("Token"))
    allowed_instances = models.ManyToManyField(WireGuardInstance, blank=True, related_name='api_keys', verbose_name=_("Allowed Instances"))
    allow_restart = models.BooleanField(default=True, verbose_name=_("Allow Restart"))
    allow_reload = models.BooleanField(default=True, verbose_name=_("Allow Reload"))
    allow_export = models.BooleanField(default=True, verbose_name=_("Allow Export"))
    enabled = models.BooleanField(default=True, verbose_name=_("Enabled"))

    uuid = models.UUIDField(default=uuid.uuid4, editable=False, unique=True)
    created = models.DateTimeField(auto_now_add=True)
    updated = models.DateTimeField(auto_now=True)

    def __str__(self):
        return self.name