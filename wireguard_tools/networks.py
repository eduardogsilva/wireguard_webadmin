import ipaddress


def normalize_cidr_list(cidr_list):
    """
    Receives a list of strings like ['10.0.0.1/24', '10.0.0.0/24'].
    Returns a sorted unique list of canonical CIDRs (strict=False).
    Invalid items are ignored.
    """
    normalized = set()
    for item in cidr_list or []:
        if not item:
            continue
        try:
            normalized.add(str(ipaddress.ip_network(item, strict=False)))
        except Exception:
            continue
    return sorted(normalized)


def normalize_cidr_pairs(ip_netmask_pairs):
    """
    Receives an iterable of (ip, netmask) pairs and returns a sorted unique list
    of canonical CIDRs (strict=False). Invalid items are ignored.
    """
    cidrs = []
    for ip, netmask in ip_netmask_pairs or []:
        if ip is None or netmask is None:
            continue
        cidrs.append(f"{ip}/{netmask}")
    return normalize_cidr_list(cidrs)


def safe_network_cidr(address, netmask):
    """
    Returns the network CIDR for an address/netmask, or None if invalid.
    """
    try:
        network = ipaddress.ip_network(f"{address}/{netmask}", strict=False)
        return str(network)
    except Exception:
        return None
