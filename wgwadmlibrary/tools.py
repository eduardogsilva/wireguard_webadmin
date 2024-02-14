import ipaddress, re


def is_valid_ip_or_hostname(value):
    """Check if a given string is a valid IP address or hostname."""
    try:
        ipaddress.ip_address(value)
        return True
    except:
        pass
    
    # Regex to check valid hostname (RFC 1123)
    hostname_regex = r'^((?!-)[A-Za-z0-9-]{1,63}(?<!-)\.)+[A-Za-z]{2,6}$' 
    if re.match(hostname_regex, value):
        return True
    
    return False
