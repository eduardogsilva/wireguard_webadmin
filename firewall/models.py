from django.db import models
from wireguard.models import Peer, WireGuardInstance
import uuid


class RedirectRule(models.Model):
    description = models.CharField(max_length=100, blank=True, null=True)
    protocol = models.CharField(max_length=3, default='tcp', choices=[('tcp', 'TCP'), ('udp', 'UDP')])
    port = models.PositiveIntegerField(default=8080)
    add_forward_rule = models.BooleanField(default=True)
    masquerade_source = models.BooleanField(default=False)
    peer = models.ForeignKey(Peer, on_delete=models.CASCADE, blank=True, null=True)
    wireguard_instance = models.ForeignKey(WireGuardInstance, on_delete=models.CASCADE, blank=True, null=True)
    ip_address = models.GenericIPAddressField(blank=True, null=True, protocol='IPv4')
    
    created = models.DateTimeField(auto_now_add=True)
    updated = models.DateTimeField(auto_now=True)
    uuid = models.UUIDField(primary_key=True, editable=False, default=uuid.uuid4)

    def __str__(self):
        return self.protocol + '/' + str(self.port)
    
    class Meta:
        unique_together = ['port', 'protocol']


