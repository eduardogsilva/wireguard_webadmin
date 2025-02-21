import ipaddress, re
import subprocess
from wireguard.models import Peer, WireGuardInstance
from user_manager.models import UserAcl
from django.db.models import Max


def user_has_access_to_instance(user_acl: UserAcl, instance: WireGuardInstance):
    if user_acl.peer_groups.all():
        if user_acl.peer_groups.filter(server_instance=instance).exists():
            return True
    else:
        return True
    return False


def user_has_access_to_peer(user_acl: UserAcl, peer: Peer):
    if user_acl.peer_groups.all():
        if user_acl.peer_groups.filter(peer=peer).exists():
            return True
        if user_acl.peer_groups.filter(server_instance=peer.wireguard_instance).exists():
            return True
    else:
        return True
    return False


def user_allowed_instances(user_acl: UserAcl):
    if not user_acl.peer_groups.exists():
        return WireGuardInstance.objects.all().order_by('instance_id')
    instances_from_groups = WireGuardInstance.objects.filter(peergroup__in=user_acl.peer_groups.all())    
    instances_from_peers = WireGuardInstance.objects.filter(peer__peergroup__in=user_acl.peer_groups.all())
    return instances_from_groups.union(instances_from_peers).order_by('instance_id')


def user_allowed_peers(user_acl: UserAcl, instance: WireGuardInstance):

    if not user_acl.peer_groups.exists():
        return Peer.objects.filter(wireguard_instance=instance).order_by('sort_order')

    peers_from_direct = Peer.objects.filter(
        wireguard_instance=instance,
        peergroup__in=user_acl.peer_groups.all()
    )
    
    peers_from_instance = Peer.objects.filter(
        wireguard_instance=instance,
        wireguard_instance__peergroup__in=user_acl.peer_groups.filter(server_instance=instance)
    )

    return peers_from_direct.union(peers_from_instance).order_by('sort_order')


def is_valid_ip_or_hostname(value):
    """Check if a given string is a valid IP address or hostname."""
    try:
        ipaddress.ip_address(value)
        return True
    except:
        pass
    
    # Regex to check valid hostname (RFC 1123)
    hostname_regex = r'^((?!-)[A-Za-z0-9-]{1,63}(?<!-)\.)+[A-Za-z]{2,18}$' 
    if re.match(hostname_regex, value):
        return True
    
    return False


def list_network_interfaces():
    # Executa o comando 'ip link show' com grep para filtrar linhas com 'UP'
    cmd = "ip link show | grep UP"
    cmd_output = subprocess.check_output(cmd, shell=True, text=True)

    # Processa a saída para extrair os nomes das interfaces
    interfaces = []
    for line in cmd_output.split('\n'):
        if line:  # Verifica se a linha não está vazia
            parts = line.split(': ')
            if len(parts) > 1:
                # O nome da interface está na segunda posição após o split
                interface_name = parts[1].split('@')[0]  # Remove qualquer coisa após '@'
                interfaces.append(interface_name)

    return interfaces


def default_sort_peers(wireguard_instance: WireGuardInstance):
    unsorted_peers = Peer.objects.filter(wireguard_instance=wireguard_instance, sort_order__lte=0).order_by('created')
    highest_sort_order = Peer.objects.filter(wireguard_instance=wireguard_instance).aggregate(Max('sort_order'))['sort_order__max']
    if not highest_sort_order:
        highest_sort_order = 0
    if unsorted_peers:
        new_sort_order = highest_sort_order + 1
        for peer in unsorted_peers:
            peer.sort_order = new_sort_order
            peer.save()
            new_sort_order += 1
    return unsorted_peers


def deduplicate_sort_order(wireguard_instance: WireGuardInstance):
    peers = Peer.objects.filter(wireguard_instance=wireguard_instance)
    for peer in peers:
        duplicated_peers = peers.filter(sort_order=peer.sort_order).exclude(uuid=peer.uuid)
        for duplicated_peer in duplicated_peers:
            duplicated_peer.sort_order = 0
            duplicated_peer.save()
    return peers


def check_sort_order_conflict(peer: Peer):
    peers = Peer.objects.filter(wireguard_instance=peer.wireguard_instance, sort_order=peer.sort_order).exclude(uuid=peer.uuid)
    if peers.exists():
        return True
    return False