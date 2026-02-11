import subprocess
from typing import Any, Dict, Optional, Tuple

from django.utils.translation import gettext_lazy as _

from routing_templates.models import RoutingTemplate
from wireguard.models import Peer, PeerAllowedIP, WireGuardInstance


def generate_peer_default(wireguard_instance):
    private_key = subprocess.check_output('wg genkey', shell=True).decode('utf-8').strip()
    public_key = subprocess.check_output(f'echo {private_key} | wg pubkey', shell=True).decode('utf-8').strip()
    pre_shared_key = subprocess.check_output('wg genpsk', shell=True).decode('utf-8').strip()
    default_routing_template = RoutingTemplate.objects.filter(wireguard_instance=wireguard_instance, default_template=True).first()
    free_ip_address = wireguard_instance.next_available_ip_address

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


def func_create_new_peer(
        wireguard_instance: WireGuardInstance,
        overrides: Optional[Dict[str, Any]] = None,
) -> Tuple[Optional[Peer], str]:
    """
    Creates a new Peer using generate_peer_default(), allowing optional overrides.

    Supported override keys:
      - name
      - public_key
      - pre_shared_key
      - persistent_keepalive
      - private_key
      - allowed_ip
      - default_routing_template
      - allowed_ip_netmask (defaults to 32)
    """
    new_peer_data = generate_peer_default(wireguard_instance)

    overrides = overrides or {}

    # avoid accidental mismatch / footguns
    forbidden_keys = {'wireguard_instance'}
    for k in forbidden_keys:
        if k in overrides:
            raise ValueError(f'Override not allowed: {k}')

    if overrides.get('allowed_ip'):
        if not wireguard_instance.check_available_ip_address(overrides.get('allowed_ip')):
            return None, str(_('Error creating peer|The specified IP address is not available.'))

    # apply overrides last
    new_peer_data.update(overrides)

    allowed_ip_netmask = int(new_peer_data.get('allowed_ip_netmask', 32) or 32)

    if new_peer_data.get('allowed_ip'):
        new_peer = Peer.objects.create(
            name=new_peer_data.get('name', ''),
            public_key=new_peer_data['public_key'],
            pre_shared_key=new_peer_data['pre_shared_key'],
            persistent_keepalive=new_peer_data.get('persistent_keepalive', 25),
            private_key=new_peer_data.get('private_key'),
            wireguard_instance=wireguard_instance,
            routing_template=new_peer_data.get('default_routing_template'),
        )

        PeerAllowedIP.objects.create(
            config_file='server',
            peer=new_peer,
            allowed_ip=new_peer_data['allowed_ip'],
            priority=0,
            netmask=allowed_ip_netmask,
        )

        message = str(_('Peer created|Peer created successfully.'))
        return new_peer, message

    message = str(_('Error creating peer|No available IP address found for peer creation.'))
    return None, message
