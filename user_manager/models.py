import uuid

from django.contrib.auth.models import User
from django.db import models
from django.utils.translation import gettext_lazy as _

from wireguard.models import PeerGroup


class UserAcl(models.Model):
    user = models.OneToOneField(User, on_delete=models.CASCADE)
    user_level = models.PositiveIntegerField(default=0, choices=(
        (10, _('Debugging Analyst')),
        (20, _('View Only')),
        (30, _('Peer Manager')),
        (40, _('WireGuard Manager')),
        (50, _('Administrator')),
    ))
    peer_groups = models.ManyToManyField(PeerGroup, blank=True)
    enable_console = models.BooleanField(default=True)
    enable_enhanced_filter = models.BooleanField(default=False)
    enable_reload = models.BooleanField(default=True)
    enable_restart = models.BooleanField(default=True)

    created = models.DateTimeField(auto_now_add=True)
    updated = models.DateTimeField(auto_now=True)
    uuid = models.UUIDField(primary_key=True, editable=False, default=uuid.uuid4)

    def __str__(self):
        return self.user.username


class AuthenticationToken(models.Model):
    user = models.ForeignKey(User, on_delete=models.CASCADE)
    created = models.DateTimeField(auto_now_add=True)
    updated = models.DateTimeField(auto_now=True)
    uuid = models.UUIDField(editable=False, default=uuid.uuid4)
