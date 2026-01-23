import uuid

from django.db import models, transaction
from django.utils.translation import gettext_lazy as _

from wireguard.models import WireGuardInstance
from wireguard.models import WireGuardInstance, PeerAllowedIP
from wireguard_tools.networks import normalize_cidr_list


class RoutingTemplate(models.Model):
    ROUTE_TYPE_CHOICES = [
        ("default", _('Default Route (0.0.0.0/0)')),
        ("peer_same_instance", _('Routes from Peers on same Interface')),
        ("peer_all_instances", _('Routes from All Peers')),
        ("custom", _('Custom Routes')),
    ]

    wireguard_instance = models.ForeignKey(WireGuardInstance, on_delete=models.CASCADE)
    default_template = models.BooleanField(default=False)

    name = models.CharField(max_length=32)
    route_type = models.CharField(max_length=20, choices=ROUTE_TYPE_CHOICES)

    custom_routes = models.TextField(blank=True, null=True, help_text=_('One route per line in CIDR notation.'))
    allow_peer_custom_routes = models.BooleanField(default=False)
    enforce_route_policy = models.BooleanField(default=False)

    uuid = models.UUIDField(default=uuid.uuid4, editable=False, unique=True)
    created = models.DateTimeField(auto_now_add=True)
    updated = models.DateTimeField(auto_now=True)

    class Meta:
        unique_together = (("wireguard_instance", "name"),)

    def __str__(self):
        return self.name

    def save(self, *args, **kwargs):
        with transaction.atomic():
            super().save(*args, **kwargs)
            if self.default_template:
                (
                    RoutingTemplate.objects
                    .filter(wireguard_instance=self.wireguard_instance, default_template=True)
                    .exclude(pk=self.pk)
                    .update(default_template=False)
                )

    @property
    def template_routes(self):
        if self.route_type == 'default':
            return ['0.0.0.0/0']

        routes = []

        if self.route_type == 'peer_same_instance':
            if self.wireguard_instance.network_cidr:
                routes.append(self.wireguard_instance.network_cidr)
            routes.extend(self.wireguard_instance.peer_announced_networks)

        elif self.route_type == 'peer_all_instances':
            for wg in WireGuardInstance.objects.all().order_by('instance_id'):
                if wg.network_cidr and wg.network_cidr not in routes:
                    routes.append(wg.network_cidr)
                routes.extend(wg.peer_announced_networks)

        if self.custom_routes:
            for raw_line in self.custom_routes.splitlines():
                line = (raw_line or '').strip()
                if line:
                    routes.append(line)

        return normalize_cidr_list(routes)
