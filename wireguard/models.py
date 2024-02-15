from django.db import models
import uuid

NETMASK_CHOICES = (
        (8, '/8 (255.0.0.0)'),
        (9, '/9 (255.128.0.0)'),
        (10, '/10 (255.192.0.0)'),
        (11, '/11 (255.224.0.0)'),
        (12, '/12 (255.240.0.0)'),
        (13, '/13 (255.248.0.0)'),
        (14, '/14 (255.252.0.0)'),
        (15, '/15 (255.254.0.0)'),
        (16, '/16 (255.255.0.0)'),
        (17, '/17 (255.255.128.0)'),
        (18, '/18 (255.255.192.0)'),
        (19, '/19 (255.255.224.0)'),
        (20, '/20 (255.255.240.0)'),
        (21, '/21 (255.255.248.0)'),
        (22, '/22 (255.255.252.0)'),
        (23, '/23 (255.255.254.0)'),
        (24, '/24 (255.255.255.0)'),
        (25, '/25 (255.255.255.128)'),
        (26, '/26 (255.255.255.192)'),
        (27, '/27 (255.255.255.224)'),
        (28, '/28 (255.255.255.240)'),
        (29, '/29 (255.255.255.248)'),
        (30, '/30 (255.255.255.252)'),
        (32, '/32 (255.255.255.255)'),
    )


class WireGuardInstance(models.Model):
    name = models.CharField(max_length=100, blank=True, null=True)
    instance_id = models.PositiveIntegerField(unique=True, default=0)
    private_key = models.CharField(max_length=100)
    public_key = models.CharField(max_length=100)
    hostname = models.CharField(max_length=100)
    listen_port = models.IntegerField(default=51820, unique=True)
    address = models.GenericIPAddressField(unique=True, protocol='IPv4')
    netmask = models.IntegerField(default=24, choices=NETMASK_CHOICES)
    post_up = models.TextField(blank=True, null=True)
    post_down = models.TextField(blank=True, null=True)
    persistent_keepalive = models.IntegerField(default=25)

    created = models.DateTimeField(auto_now_add=True)
    updated = models.DateTimeField(auto_now=True)
    uuid = models.UUIDField(primary_key=True, editable=False, default=uuid.uuid4)

    def __str__(self):
        if self.name:
            return self.name    
        else:
            return 'wg' + str(self.instance_id)


class Peer(models.Model):
    name = models.CharField(max_length=100, blank=True, null=True)
    public_key = models.CharField(max_length=100)
    pre_shared_key = models.CharField(max_length=100)
    private_key = models.CharField(max_length=100, blank=True, null=True)
    persistent_keepalive = models.IntegerField(default=25)
    wireguard_instance = models.ForeignKey(WireGuardInstance, on_delete=models.CASCADE)

    created = models.DateTimeField(auto_now_add=True)
    updated = models.DateTimeField(auto_now=True)
    uuid = models.UUIDField(primary_key=True, editable=False, default=uuid.uuid4)

    def __str__(self):
        if self.name:
            return self.name
        else:
            return self.public_key


class PeerAllowedIP(models.Model):
    peer = models.ForeignKey(Peer, on_delete=models.CASCADE)
    priority = models.PositiveBigIntegerField(default=1)
    allowed_ip = models.GenericIPAddressField(protocol='IPv4')
    netmask = models.IntegerField(default=32, choices=NETMASK_CHOICES)
    missing_from_wireguard = models.BooleanField(default=False)

    created = models.DateTimeField(auto_now_add=True)
    updated = models.DateTimeField(auto_now=True)
    uuid = models.UUIDField(primary_key=True, editable=False, default=uuid.uuid4)

    def __str__(self):
        return str(self.allowed_ip) + '/' + str(self.netmask)
    