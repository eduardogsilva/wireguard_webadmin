from firewall.models import FirewallRule
from wireguard.models import Peer, PeerAllowedIP

def get_peer_addresses(peers, include_networks):
    addresses = []
    # Indica se algum peer está completamente sem PeerAllowedIP
    missing_ip = False
    for peer in peers.all():
        peer_ips = peer.peerallowedip_set.all().order_by('priority')
        if not include_networks:
            peer_ips = peer_ips.filter(priority=0)
        
        if peer_ips.exists():
            addresses.extend([f"{peer_ip.allowed_ip}/{peer_ip.netmask}" for peer_ip in peer_ips])
        else:
            missing_ip = True
    
    return addresses, missing_ip

def generate_iptable_rules():
    iptables_rules = []
    rules = FirewallRule.objects.all().order_by('firewall_chain', 'sort_order')

    for rule in rules:
        source_addresses, source_missing_ip = get_peer_addresses(rule.source_peer, rule.source_peer_include_networks)
        destination_addresses, destination_missing_ip = get_peer_addresses(rule.destination_peer, rule.destination_peer_include_networks)

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
                for destination in destination_addresses:
                    description = f" - {rule.description}" if rule.description else ""
                    comment = f"\n# {rule.sort_order} - {rule.uuid}{description}"
                    # Pula a geração de regra se um dos peers estiver faltando IP e for relevante para essa combinação
                    if (source is None and source_missing_ip) or (destination is None and destination_missing_ip):
                        iptables_rule = f"{comment} - Missing ip for selected peer\n"
                        iptables_rules.append(iptables_rule)
                        continue
                    comment += '\n'
                    if rule.firewall_chain == "forward":
                        rule_base = "iptables -t filter -A FORWARD "
                    elif rule.firewall_chain == "postrouting":
                        rule_base = "iptables -t nat -A POSTROUTING "
                    else:
                        rule_base = f"#iptables -A {rule.firewall_chain.upper()} "
                    rule_protocol = f"-p {protocol} " if protocol else ""
                    rule_destination_port = f"--dport {rule.destination_port} " if rule.destination_port else ""
                    rule_source = f"-s {source} " if source else ""
                    rule_destination = f"-d {destination} " if destination else ""
                    rule_action = f"-j {rule.rule_action.upper()}"

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
                    

                    iptables_rule = f"{comment}{rule_base}{not_source}{rule_source}{not_destination}{rule_destination}{rule_state}{rule_protocol}{rule_destination_port}{rule_action}\n"
                    iptables_rules.append(iptables_rule)

    return "".join(iptables_rules)

