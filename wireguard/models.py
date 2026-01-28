import uuid

from django.db import models

from wireguard_tools.networks import normalize_cidr_list, normalize_cidr_pairs, safe_network_cidr

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


class WebadminSettings(models.Model):
    name = models.CharField(default='webadmin_settings', max_length=20, unique=True)
    db_patch_version = models.IntegerField(default=0)
    update_available = models.BooleanField(default=False)
    current_version = models.PositiveIntegerField(default=0)
    latest_version = models.PositiveIntegerField(default=0)
    last_checked = models.DateTimeField(blank=True, null=True)

    updated = models.DateTimeField(auto_now=True)
    created = models.DateTimeField(auto_now_add=True)
    uuid = models.UUIDField(default=uuid.uuid4, editable=False, unique=True)

    def __str__(self):
        return self.name


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
    peer_list_refresh_interval = models.IntegerField(default=10)
    dns_primary = models.GenericIPAddressField(unique=False, protocol='IPv4', default='1.1.1.1', blank=True, null=True)
    dns_secondary = models.GenericIPAddressField(unique=False, protocol='IPv4', default='1.0.0.1', blank=True, null=True)
    pending_changes = models.BooleanField(default=True)
    legacy_firewall = models.BooleanField(default=False)
    enforce_route_policy = models.BooleanField(default=False)

    created = models.DateTimeField(auto_now_add=True)
    updated = models.DateTimeField(auto_now=True)
    uuid = models.UUIDField(primary_key=True, editable=False, default=uuid.uuid4)

    def __str__(self):
        if self.name:
            return self.name    
        else:
            return 'wg' + str(self.instance_id)

    @property
    def network_cidr(self):
        return safe_network_cidr(self.address, self.netmask)

    @property
    def peer_announced_networks(self):
        rows = (
            PeerAllowedIP.objects
            .filter(
                peer__wireguard_instance=self,
                config_file='server',
                priority__gte=1
            )
            .values_list('allowed_ip', 'netmask')
        )
        return normalize_cidr_pairs(rows)

    @property
    def peer_main_addresses(self):
        rows = (
            PeerAllowedIP.objects
            .filter(
                peer__wireguard_instance=self,
                config_file='server',
                priority=0
            )
            .values_list('allowed_ip', 'netmask')
        )
        return normalize_cidr_pairs(rows)


class Peer(models.Model):
    name = models.CharField(max_length=100, blank=True, null=True)
    public_key = models.CharField(max_length=100)
    pre_shared_key = models.CharField(max_length=100)
    private_key = models.CharField(max_length=100, blank=True, null=True)
    persistent_keepalive = models.IntegerField(default=25)
    wireguard_instance = models.ForeignKey(WireGuardInstance, on_delete=models.CASCADE)
    sort_order = models.IntegerField(default=0)
    routing_template = models.ForeignKey(
        'routing_templates.RoutingTemplate', on_delete=models.SET_NULL, blank=True, null=True, related_name='peers'
    )

    enabled_by_schedule = models.BooleanField(default=True)
    suspended = models.BooleanField(default=False)
    suspend_reason = models.TextField(blank=True, null=True)

    created = models.DateTimeField(auto_now_add=True)
    updated = models.DateTimeField(auto_now=True)
    uuid = models.UUIDField(primary_key=True, editable=False, default=uuid.uuid4)

    def __str__(self):
        if self.name:
            return self.name
        else:
            return self.public_key[:16] + "..."

    @property
    def enabled(self) -> bool:
        return self.enabled_by_schedule and not self.suspended

    @property
    def announced_networks(self):
        prefetched = getattr(self, "_prefetched_objects_cache", {})
        if "peerallowedip_set" in prefetched:
            rows = [
                (aip.allowed_ip, aip.netmask)
                for aip in prefetched["peerallowedip_set"]
                if aip.config_file == "server" and aip.priority >= 1
            ]
            return normalize_cidr_pairs(rows)

        rows = (
            self.peerallowedip_set
            .filter(config_file='server', priority__gte=1)
            .values_list('allowed_ip', 'netmask')
        )
        return normalize_cidr_pairs(rows)

    @property
    def client_routes(self):
        routes = []

        prefetched = getattr(self, "_prefetched_objects_cache", {})
        if "peerallowedip_set" in prefetched:
            allowedips = prefetched["peerallowedip_set"]

            rows_client = [(aip.allowed_ip, aip.netmask) for aip in allowedips if aip.config_file == "client"]
            routes.extend(normalize_cidr_pairs(rows_client))

            if self.routing_template:
                routes.extend(self.routing_template.template_routes)

            normalized = normalize_cidr_list(routes)

            rows_announced = [(aip.allowed_ip, aip.netmask) for aip in allowedips if aip.config_file == "server"]
            exclude = set(normalize_cidr_pairs(rows_announced))

            final_routes = [cidr for cidr in normalized if cidr not in exclude]
            if not final_routes or "0.0.0.0/0" in final_routes:
                return ["0.0.0.0/0"]
            return final_routes

        # Fallback (no prefetch): your original DB-based implementation
        rows_client = (
            self.peerallowedip_set
            .filter(config_file='client')
            .values_list('allowed_ip', 'netmask')
        )
        routes.extend(normalize_cidr_pairs(rows_client))

        if self.routing_template:
            routes.extend(self.routing_template.template_routes)

        normalized = normalize_cidr_list(routes)

        rows_announced = (
            self.peerallowedip_set
            .filter(config_file='server')
            .values_list('allowed_ip', 'netmask')
        )
        exclude = set(normalize_cidr_pairs(rows_announced))

        final_routes = [cidr for cidr in normalized if cidr not in exclude]

        if not final_routes or '0.0.0.0/0' in final_routes:
            return ['0.0.0.0/0']
        return final_routes

    @property
    def main_addresses(self):
        prefetched = getattr(self, "_prefetched_objects_cache", {})
        if "peerallowedip_set" in prefetched:
            rows = [
                (aip.allowed_ip, aip.netmask)
                for aip in prefetched["peerallowedip_set"]
                if aip.config_file == "server" and aip.priority == 0
            ]
            return normalize_cidr_pairs(rows)

        rows = (
            self.peerallowedip_set
            .filter(config_file='server', priority=0)
            .values_list('allowed_ip', 'netmask')
        )
        return normalize_cidr_pairs(rows)

    @property
    def is_route_policy_restricted(self) -> bool:
        # 1) Enforcement must be enabled somewhere (template OR instance).
        template_enforced = bool(self.routing_template and self.routing_template.enforce_route_policy)
        instance_enforced = bool(self.wireguard_instance and self.wireguard_instance.enforce_route_policy)
        if not (template_enforced or instance_enforced):
            return False

        # 2) If there is a routing template assigned, and its type is "default", the peer is not restricted.
        if self.routing_template:
            if self.routing_template.route_type == "default":
                return False
            else:
                return True

        # 3) If there is any client-side allowed IP entry, the peer has explicit (non-default) registered routes.
        #    - If peerallowedip_set was prefetched, we scan in-memory.
        #    - Otherwise, we issue a single EXISTS() query.
        prefetched = getattr(self, "_prefetched_objects_cache", {})
        if "peerallowedip_set" in prefetched:
            has_client_routes = any(aip.config_file == "client" for aip in prefetched["peerallowedip_set"])
        else:
            has_client_routes = self.peerallowedip_set.filter(config_file="client").exists()

        if has_client_routes:
            return True

        # 5) Otherwise, the peer effectively falls back to default route (0.0.0.0/0), so it is not restricted.
        return False


class PeerStatus(models.Model):
    peer = models.OneToOneField(Peer, on_delete=models.CASCADE)
    last_handshake = models.DateTimeField(blank=True, null=True)
    transfer_rx = models.BigIntegerField(default=0)
    transfer_tx = models.BigIntegerField(default=0)
    latest_config = models.TextField(blank=True, null=True)

    created = models.DateTimeField(auto_now_add=True)
    updated = models.DateTimeField(auto_now=True)
    uuid = models.UUIDField(primary_key=True, editable=False, default=uuid.uuid4)

    def __str__(self):
        return str(self.peer)


class PeerAllowedIP(models.Model):
    peer = models.ForeignKey(Peer, on_delete=models.CASCADE)
    priority = models.PositiveBigIntegerField(default=1)
    allowed_ip = models.GenericIPAddressField(protocol='IPv4')
    netmask = models.IntegerField(default=32, choices=NETMASK_CHOICES)
    config_file = models.CharField(max_length=6, choices=(('server', 'Server Config'), ('client', 'Client config')), default='server')

    created = models.DateTimeField(auto_now_add=True)
    updated = models.DateTimeField(auto_now=True)
    uuid = models.UUIDField(primary_key=True, editable=False, default=uuid.uuid4)

    def __str__(self):
        return str(self.allowed_ip) + '/' + str(self.netmask)


class PeerGroup(models.Model):
    name = models.CharField(max_length=100, unique=True)
    peer = models.ManyToManyField(Peer, blank=True)
    server_instance = models.ManyToManyField(WireGuardInstance, blank=True)

    created = models.DateTimeField(auto_now_add=True)
    updated = models.DateTimeField(auto_now=True)
    uuid = models.UUIDField(primary_key=True, editable=False, default=uuid.uuid4)

    def __str__(self):
        return self.name

