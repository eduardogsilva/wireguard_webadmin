import ipaddress, re
import subprocess
from wireguard.models import Peer, WireGuardInstance
from user_manager.models import UserAcl


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
        return Peer.objects.filter(wireguard_instance=instance).order_by('name')

    peers_from_direct = Peer.objects.filter(
        wireguard_instance=instance,
        peergroup__in=user_acl.peer_groups.all()
    )
    
    peers_from_instance = Peer.objects.filter(
        wireguard_instance=instance,
        wireguard_instance__peergroup__in=user_acl.peer_groups.filter(server_instance=instance)
    )

    return peers_from_direct.union(peers_from_instance).order_by('name')


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
