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
    recursion: yes    
'''
    unbound_config += forward_zone
    for static_host in static_hosts:
        unbound_config += f'local-data: "{static_host.hostname}. IN A {static_host.ip_address}"\n'
    return unbound_config
