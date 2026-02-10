import ipaddress
import subprocess

from django.utils.translation import gettext_lazy as _

from routing_templates.models import RoutingTemplate
from wireguard.models import Peer, PeerAllowedIP, WireGuardInstance


def generate_peer_default(wireguard_instance):
    private_key = subprocess.check_output('wg genkey', shell=True).decode('utf-8').strip()
    public_key = subprocess.check_output(f'echo {private_key} | wg pubkey', shell=True).decode('utf-8').strip()
    pre_shared_key = subprocess.check_output('wg genpsk', shell=True).decode('utf-8').strip()

    address = wireguard_instance.address
    netmask = wireguard_instance.netmask
    cidr_network = f"{address}/{netmask}"
    network = ipaddress.ip_network(cidr_network, strict=False)

    # the code below can be an issue for larger networks, for now it's fine, but it should be optimized in the future
    used_ips = set(WireGuardInstance.objects.all().values_list('address', flat=True)) | \
               set(PeerAllowedIP.objects.filter(config_file='server', priority=0).values_list('allowed_ip', flat=True))

    free_ip_address = None
    for ip in network.hosts():
        if str(ip) not in used_ips:
            free_ip_address = str(ip)
            break

    default_routing_template = RoutingTemplate.objects.filter(wireguard_instance=wireguard_instance, default_template=True).first()

    return {
        'name': '',
        'public_key': public_key,
        'pre_shared_key': pre_shared_key,
        'persistent_keepalive': 25,
        'private_key': private_key,
        'wireguard_instance': wireguard_instance,
        'allowed_ip': free_ip_address,
        'default_routing_template': default_routing_template,
    }


def func_create_new_peer(wireguard_instance: WireGuardInstance):
    new_peer_data = generate_peer_default(wireguard_instance)

    if new_peer_data['allowed_ip']:
        new_peer = Peer.objects.create(
            name=new_peer_data['name'],
            public_key=new_peer_data['public_key'],
            pre_shared_key=new_peer_data['pre_shared_key'],
            persistent_keepalive=new_peer_data['persistent_keepalive'],
            private_key=new_peer_data['private_key'],
            wireguard_instance=wireguard_instance,
            routing_template=new_peer_data['default_routing_template'],
        )
        PeerAllowedIP.objects.create(
            config_file='server',
            peer=new_peer,
            allowed_ip=new_peer_data['allowed_ip'],
            priority=0,
            netmask=32,
        )
        message = _('Peer created|Peer created successfully.')
        return new_peer, message
    else:
        message = _('Error creating peer|No available IP address found for peer creation.')
        return None, message
