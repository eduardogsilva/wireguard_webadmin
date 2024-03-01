import ipaddress, re
import subprocess


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