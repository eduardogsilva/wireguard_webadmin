from django.db import models
from wireguard.models import Peer, WireGuardInstance
from wireguard.models import NETMASK_CHOICES
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


class FirewallRule(models.Model):
    description = models.CharField(max_length=100, blank=True, null=True)
    firewall_chain = models.CharField(max_length=12, default='forward', choices=[('forward', 'FORWARD'), ('postrouting', 'POSTROUTING (nat)')])

    in_interface = models.CharField(max_length=12, default='', blank=True, null=True)
    out_interface = models.CharField(max_length=12, default='', blank=True, null=True)

    source_ip = models.GenericIPAddressField(blank=True, null=True, protocol='IPv4')
    source_netmask = models.PositiveIntegerField(default=32, choices=NETMASK_CHOICES)
    source_peer = models.ManyToManyField(Peer, related_name="forward_rules_as_source", blank=True)
    source_peer_include_networks = models.BooleanField(default=False)
    not_source = models.BooleanField(default=False)

    destination_ip = models.GenericIPAddressField(blank=True, null=True, protocol='IPv4')
    destination_netmask = models.PositiveIntegerField(default=32, choices=NETMASK_CHOICES)
    destination_peer = models.ManyToManyField(Peer, related_name="forward_rules_as_destination", blank=True)
    destination_peer_include_networks = models.BooleanField(default=False)
    not_destination = models.BooleanField(default=False)

    protocol = models.CharField(max_length=4, default='', blank=True, null=True, choices=[('', 'all'), ('tcp', 'TCP'), ('udp', 'UDP'), ('both', 'TCP+UDP'), ('icmp', 'ICMP'),])
    destination_port = models.CharField(max_length=11, blank=True, null=True)

    state_new = models.BooleanField(default=False)
    state_related = models.BooleanField(default=False)
    state_established = models.BooleanField(default=False)
    state_invalid = models.BooleanField(default=False)
    state_untracked = models.BooleanField(default=False)
    not_state = models.BooleanField(default=False)

    rule_action = models.CharField(max_length=10, default='accept', choices=[('accept', 'ACCEPT'), ('reject', 'REJECT'), ('drop', 'DROP'), ('masquerade', 'MASQUERADE')])
    
    sort_order = models.PositiveIntegerField(default=0)
    created = models.DateTimeField(auto_now_add=True)
    updated = models.DateTimeField(auto_now=True)
    uuid = models.UUIDField(primary_key=True, editable=False, default=uuid.uuid4)

    def __str__(self):
        return str(self.uuid)


class FirewallSettings(models.Model):
    name = models.CharField(max_length=6, default='global', unique=True)
    default_forward_policy = models.CharField(max_length=6, default='accept', choices=[('accept', 'ACCEPT'), ('reject', 'REJECT'), ('drop', 'DROP')])
    default_output_policy = models.CharField(max_length=6, default='accept', choices=[('accept', 'ACCEPT'), ('reject', 'REJECT'), ('drop', 'DROP')])
    allow_peer_to_peer = models.BooleanField(default=True)
    allow_instance_to_instance = models.BooleanField(default=True)
    wan_interface = models.CharField(max_length=12, default='eth0')
    pending_changes = models.BooleanField(default=False)

    created = models.DateTimeField(auto_now_add=True)
    updated = models.DateTimeField(auto_now=True)

