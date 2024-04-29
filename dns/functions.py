from .models import DNSSettings, StaticHost


def generate_unbound_config():
    dns_settings = DNSSettings.objects.get(name='dns_settings')
    static_hosts = StaticHost.objects.all()
    if dns_settings.dns_primary:
        do_not_query_localhost = 'yes'
        forward_zone = f'\nforward-zone:\n    name: "."\n    forward-addr: {dns_settings.dns_primary}\n'
        if dns_settings.dns_secondary:
            forward_zone += f'    forward-addr: {dns_settings.dns_secondary}\n'
    else:
        do_not_query_localhost = 'no'
        forward_zone = ''


    unbound_config = f'''
server:
    interface: 0.0.0.0
    port: 53
    access-control: 0.0.0.0/0 allow
    do-ip4: yes
    do-ip6: no
    do-udp: yes
    local-zone: "local." static
    do-not-query-localhost: {do_not_query_localhost}
    verbosity: 1
'''
    unbound_config += forward_zone

    if static_hosts:
        unbound_config += '\nlocal-zone: "." transparent\n'
        for static_host in static_hosts:
            unbound_config += f'    local-data: "{static_host.hostname}. IN A {static_host.ip_address}"\n'
    return unbound_config


def generate_dnsdist_config():
    dns_settings = DNSSettings.objects.get(name='dns_settings')
    static_hosts = StaticHost.objects.all()
    dnsdist_config = "setLocal('0.0.0.0:53')\n"
    dnsdist_config += "setACL('0.0.0.0/0')\n"

    if dns_settings.dns_primary:
        dnsdist_config += f"newServer({{address='{dns_settings.dns_primary}', pool='upstreams'}})\n"
    if dns_settings.dns_secondary:
        dnsdist_config += f"newServer({{address='{dns_settings.dns_secondary}', pool='upstreams'}})\n"

    if static_hosts:
        dnsdist_config += "addAction(makeRule(''), PoolAction('staticHosts'))\n"
        for static_host in static_hosts:
            dnsdist_config += f"addLocal('{static_host.hostname}', '{static_host.ip_address}')\n"

    return dnsdist_config


def generate_dnsmasq_config():
    dns_settings = DNSSettings.objects.get(name='dns_settings')
    static_hosts = StaticHost.objects.all()
    dnsmasq_config = f'''
no-dhcp-interface=
listen-address=0.0.0.0
bind-interfaces
    
'''
    if dns_settings.dns_primary:
        dnsmasq_config += f'server={dns_settings.dns_primary}\n'
    if dns_settings.dns_secondary:
        dnsmasq_config += f'server={dns_settings.dns_secondary}\n'

    if static_hosts:
        dnsmasq_config += '\n'
        for static_host in static_hosts:
            dnsmasq_config += f'address=/{static_host.hostname}/{static_host.ip_address}\n'
    return dnsmasq_config
