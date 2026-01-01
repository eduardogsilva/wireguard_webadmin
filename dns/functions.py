import os
import tarfile

from cluster.models import ClusterSettings
from .models import DNSSettings, StaticHost, DNSFilterList


def compress_dnsmasq_config():
    output_file = "/etc/dnsmasq/dnsmasq_config.tar.gz"
    base_dir = "/etc/dnsmasq"
    cluster_settings = ClusterSettings.objects.filter(enabled=True, name='cluster_settings').first()
    if not cluster_settings:
        if os.path.exists(output_file):
            os.remove(output_file)
        return None

    if not os.path.isdir(base_dir):
        if os.path.exists(output_file):
            os.remove(output_file)
        return None

    conf_files = [
        fn for fn in os.listdir(base_dir)
        if fn.endswith(".conf") and os.path.isfile(os.path.join(base_dir, fn))
    ]

    # If tar exists and is newer (or equal) than all .conf, do not recompile
    if os.path.exists(output_file):
        tar_mtime = os.path.getmtime(output_file)
        newest_conf_mtime = max(
            os.path.getmtime(os.path.join(base_dir, fn)) for fn in conf_files
        )
        if newest_conf_mtime <= tar_mtime:
            return output_file

    # If we reach here, we need to increment DNS version and recompile the tar.gz
    cluster_settings.dns_version += 1
    cluster_settings.save()
    dns_version_file = os.path.join(base_dir, "config_version.conf")
    with open(dns_version_file, "w", encoding="utf-8") as f:
        f.write(f"DNS_VERSION={cluster_settings.dns_version}\n")
    if "config_version.conf" not in conf_files:
        conf_files.append("config_version.conf")

    # Create tar.gz
    tmp_output = output_file + ".tmp"
    with tarfile.open(tmp_output, "w:gz") as tar:
        for fn in conf_files:
            fullpath = os.path.join(base_dir, fn)
            tar.add(fullpath, arcname=fn)

    os.replace(tmp_output, output_file)
    return output_file


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
    dns_lists = DNSFilterList.objects.filter(enabled=True)
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

    if dns_lists:
        dnsmasq_config += '\n'
        for dns_list in dns_lists:
            file_path = os.path.join("/etc/dnsmasq/", f"{dns_list.uuid}.conf")
            dnsmasq_config += f'addn-hosts={file_path}\n'
    return dnsmasq_config

