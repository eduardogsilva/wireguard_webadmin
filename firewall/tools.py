from firewall.models import FirewallRule, FirewallSettings, RedirectRule
from wireguard.models import Peer, PeerAllowedIP, WireGuardInstance
from django.utils import timezone


def get_peer_addresses(peers, include_networks):
    addresses = []
    for peer in peers.all():
        peer_ips = peer.peerallowedip_set.all().order_by('priority')
        if not include_networks:
            peer_ips = peer_ips.filter(priority=0)
        
        if peer_ips.exists():
            addresses.extend([f"{peer_ip.allowed_ip}/{peer_ip.netmask}" for peer_ip in peer_ips])
        else:
            addresses.append(f"Missing IP for selected peer: {peer}")
    
    return addresses


def reset_firewall_to_default():
    for wireguard_instance in WireGuardInstance.objects.all():
        wireguard_instance.pending_changes = True
        wireguard_instance.legacy_firewall = False
        wireguard_instance.post_up = ''
        wireguard_instance.post_down = ''
        wireguard_instance.save()
    firewall_settings, firewall_settings_created = FirewallSettings.objects.get_or_create(name='global')
    firewall_settings.pending_changes = True
    firewall_settings.last_firewall_reset = timezone.now()
    firewall_settings.allow_peer_to_peer = True
    firewall_settings.allow_instance_to_instance = True
    firewall_settings.wan_interface = 'eth0'
    firewall_settings.default_forward_policy = 'drop'
    firewall_settings.save()

    FirewallRule.objects.all().delete()
    RedirectRule.objects.all().delete()

    FirewallRule.objects.create(
        firewall_chain='postrouting', sort_order=0, out_interface=firewall_settings.wan_interface, rule_action='masquerade', 
        description='Masquerade traffic from VPN to WAN',
    )

    FirewallRule.objects.create(
        firewall_chain='forward', sort_order=0, rule_action='accept', description='Allow established/related traffic', 
        state_established=True, state_related=True
        )
    FirewallRule.objects.create(
        firewall_chain='forward', sort_order=1, rule_action='reject', description='Reject traffic to private networks exiting on WAN interface',
        in_interface='wg+', out_interface=firewall_settings.wan_interface, destination_ip='10.0.0.0', destination_netmask=8
        )
    FirewallRule.objects.create(
        firewall_chain='forward', sort_order=2, rule_action='reject', description='Reject traffic to private networks exiting on WAN interface',
        in_interface='wg+', out_interface=firewall_settings.wan_interface, destination_ip='172.16.0.0', destination_netmask=12
        )
    FirewallRule.objects.create(
        firewall_chain='forward', sort_order=3, rule_action='reject', description='Reject traffic to private networks exiting on WAN interface',
        in_interface='wg+', out_interface=firewall_settings.wan_interface, destination_ip='192.168.0.0', destination_netmask=16
        )
    FirewallRule.objects.create(
        firewall_chain='forward', sort_order=10, rule_action='accept', description='Allow traffic from VPN to WAN', 
        in_interface='wg+', out_interface=firewall_settings.wan_interface
        )
    return


def export_user_firewall():
    iptables_rules = []
    rules = FirewallRule.objects.all().order_by('firewall_chain', 'sort_order')

    for rule in rules:
        source_addresses = get_peer_addresses(rule.source_peer, rule.source_peer_include_networks)
        destination_addresses = get_peer_addresses(rule.destination_peer, rule.destination_peer_include_networks)

        # Adiciona source_ip/destination_ip às listas, se definidos
        if rule.source_ip:
            source_addresses.append(f"{rule.source_ip}/{rule.source_netmask}")
        if rule.destination_ip:
            destination_addresses.append(f"{rule.destination_ip}/{rule.destination_netmask}")

        # Caso especial: se não houver endereços de source e destination, cria uma lista vazia para garantir a execução do loop
        if not source_addresses:
            source_addresses = [None]
        if not destination_addresses:
            destination_addresses = [None]

        protocols = ['tcp', 'udp'] if rule.protocol == 'both' else [rule.protocol] if rule.protocol else ['']
        
        for protocol in protocols:
            for source in source_addresses:
                if source and "Missing IP for selected peer:" in source:
                    description = f" - {rule.description}" if rule.description else ""
                    iptables_rules.append(f"# {rule.sort_order} - {rule.uuid}{description} - {source}\n")
                    continue  

                for destination in destination_addresses:
                    if destination and "Missing IP for selected peer:" in destination:
                        description = f" - {rule.description}" if rule.description else ""
                        iptables_rules.append(f"# {rule.sort_order} - {rule.uuid}{description} - {destination}\n")
                        continue

                    description = f" - {rule.description}" if rule.description else ""
                    comment = f"# {rule.sort_order} - {rule.uuid}{description}\n"
                    
                    if rule.firewall_chain == "forward":
                        rule_base = "iptables -t filter -A WGWADM_FORWARD "
                    elif rule.firewall_chain == "postrouting":
                        rule_base = "iptables -t nat -A WGWADM_POSTROUTING "
                    else:
                        rule_base = f"#iptables -A {rule.firewall_chain.upper()} "
                    rule_protocol = f"-p {protocol} " if protocol else ""
                    rule_destination_port = f"--dport {rule.destination_port} " if rule.destination_port else ""
                    rule_source = f"-s {source} " if source else ""
                    rule_destination = f"-d {destination} " if destination else ""
                    rule_action = f"-j {rule.rule_action.upper()}"
                    rule_in_interface = f"-i {rule.in_interface} " if rule.in_interface else ""
                    rule_out_interface = f"-o {rule.out_interface} " if rule.out_interface else ""

                    states = []
                    if rule.state_new:
                        states.append("NEW")
                    if rule.state_related:
                        states.append("RELATED")
                    if rule.state_established:
                        states.append("ESTABLISHED")
                    if rule.state_invalid:
                        states.append("INVALID")
                    if rule.state_untracked:
                        states.append("UNTRACKED")

                    not_state = "! " if rule.not_state and states else ""
                    rule_state = f"-m state {not_state}--state {','.join(states)} " if states else ""

                    not_source = "! " if rule.not_source and source else ""
                    not_destination = "! " if rule.not_destination and destination else ""
                    
                    iptables_rule = f"{comment}{rule_base}{rule_in_interface}{rule_out_interface}{not_source}{rule_source}{not_destination}{rule_destination}{rule_state}{rule_protocol}{rule_destination_port}{rule_action}\n"
                    iptables_rules.append(iptables_rule)

    return "".join(iptables_rules)


def generate_firewall_header():
    firewall_settings, firewall_settings_created = FirewallSettings.objects.get_or_create(name='global')
    header = f'''#!/bin/bash
# Description: Firewall rules for WireGuard_WebAdmin
# Do not edit this file directly. Use the web interface to manage firewall rules.
#
# This script was generated by WireGuard_WebAdmin on {timezone.now().strftime('%Y-%m-%d %H:%M:%S %Z')}
#

iptables -t nat    -N WGWADM_POSTROUTING >> /dev/null 2>&1
iptables -t nat    -N WGWADM_PREROUTING  >> /dev/null 2>&1
iptables -t filter -N WGWADM_FORWARD     >> /dev/null 2>&1

iptables -t nat    -F WGWADM_POSTROUTING
iptables -t nat    -F WGWADM_PREROUTING
iptables -t filter -F WGWADM_FORWARD

iptables -t nat    -D POSTROUTING -j WGWADM_POSTROUTING >> /dev/null 2>&1
iptables -t nat    -D PREROUTING  -j WGWADM_PREROUTING  >> /dev/null 2>&1
iptables -t filter -D FORWARD     -j WGWADM_FORWARD     >> /dev/null 2>&1

iptables -t nat    -I POSTROUTING -j WGWADM_POSTROUTING
iptables -t nat    -I PREROUTING  -j WGWADM_PREROUTING
iptables -t filter -I FORWARD     -j WGWADM_FORWARD
'''
    

    return header

def generate_firewall_footer():
    firewall_settings, firewall_settings_created = FirewallSettings.objects.get_or_create(name='global')
    footer = '# The following rules come from Firewall settings\n'
    footer += '# Default FORWARD policy\n'
    footer += f'iptables -t filter -P FORWARD {firewall_settings.default_forward_policy.upper()}\n'

    footer += '# Same instance Peer to Peer traffic\n'
    for wireguard_instance in WireGuardInstance.objects.all().order_by('instance_id'):
        footer += f'iptables -t filter -A WGWADM_FORWARD -i wg{wireguard_instance.instance_id} -o wg{wireguard_instance.instance_id} -j '
        footer += 'ACCEPT\n' if firewall_settings.allow_peer_to_peer else "REJECT\n"
    footer += '# Instance to Instance traffic\n'
    footer += 'iptables -t filter -A WGWADM_FORWARD -i wg+ -o wg+ -j '
    footer += 'ACCEPT\n' if firewall_settings.allow_instance_to_instance else "REJECT\n"
    return footer


def generate_port_forward_firewall():
    firewall_settings, firewall_settings_created = FirewallSettings.objects.get_or_create(name='global')
    redirect_firewall = ''
    wan_interface = firewall_settings.wan_interface

    for redirect_rule in RedirectRule.objects.all().order_by('port'):
        description = f" - {redirect_rule.description} " if redirect_rule.description else ""
        rule_destination = redirect_rule.ip_address
        if redirect_rule.peer:
            peer_allowed_ip_address = PeerAllowedIP.objects.filter(peer=redirect_rule.peer, netmask=32, priority=0).first()
            if peer_allowed_ip_address:
                rule_destination = peer_allowed_ip_address.allowed_ip
        if rule_destination:
            rule_text =  f"# {redirect_rule.port}/{redirect_rule.protocol} - {redirect_rule.uuid} - Port Forward Rule set{description}\n"
            rule_text += f"iptables -t nat    -A WGWADM_PREROUTING  -p {redirect_rule.protocol} -d wireguard-webadmin -i {wan_interface} --dport {redirect_rule.port} -j DNAT --to-dest {rule_destination}:{redirect_rule.port}\n"
            
            if redirect_rule.masquerade_source:
                rule_text   += f"iptables -t nat    -A WGWADM_POSTROUTING -p {redirect_rule.protocol} -d {rule_destination} -o wg+ --dport {redirect_rule.port} -j MASQUERADE\n"
            
            if redirect_rule.add_forward_rule:
                rule_text   += f"iptables -t filter -A WGWADM_FORWARD     -p {redirect_rule.protocol} -d {rule_destination} -i {wan_interface} -o wg+  --dport {redirect_rule.port} -j ACCEPT\n"
            
            redirect_firewall += rule_text

        else:
            rule_text =  f"# {redirect_rule.port}/{redirect_rule.protocol} - {redirect_rule.uuid} - Port Forward Rule set{description} - Missing IP for selected peer: {redirect_rule.peer}\n"
            redirect_firewall += rule_text
            
    return redirect_firewall