import ipaddress
import os
import subprocess
from typing import Union

from django.utils.translation import gettext_lazy as _

from cluster.models import ClusterSettings, Worker
from wireguard.models import WireGuardInstance

WIREGUARD_CONFIG_DIR = '/etc/wireguard'
# Configurations of instances that run on workers (distributed cluster mode). Kept out of WIREGUARD_CONFIG_DIR
# so the primary server does not bring them up.
CLUSTER_WIREGUARD_CONFIG_DIR = '/etc/wireguard/cluster'


def get_instance_config_dir(instance: WireGuardInstance) -> str:
    return CLUSTER_WIREGUARD_CONFIG_DIR if instance.hosting_worker else WIREGUARD_CONFIG_DIR


def get_config_servers(instance: WireGuardInstance) -> list:
    """Servers offered when downloading a peer configuration of the instance. Empty without the cluster."""
    cluster_settings = ClusterSettings.objects.filter(name='cluster_settings', enabled=True).first()
    if not cluster_settings:
        return []

    if ClusterSettings.is_distributed():
        hosting_worker = instance.hosting_worker if instance else None
        if hosting_worker:
            return [{'name': hosting_worker.display_name, 'uuid': str(hosting_worker.uuid)}]
        return [{'name': _('Primary Server'), 'uuid': ''}]

    servers = []
    if cluster_settings.primary_enable_wireguard:
        servers.append({'name': _('Primary Server'), 'uuid': ''})
    for worker in Worker.objects.filter(enabled=True):
        servers.append({'name': worker.display_name, 'uuid': str(worker.uuid)})
    return servers


def sync_interface_routes(interface_name: str) -> list:
    """
    Bring the IPv4 routes of a running interface in line with its allowed IPs, as wg-quick does on start.
    wg syncconf only updates the peers, so networks added to or removed from a peer would otherwise only
    get their routes on the next restart. Default routes (/0) are left to wg-quick. Returns the errors found.
    """
    errors = []
    allowed_ips_result = subprocess.run(['wg', 'show', interface_name, 'allowed-ips'], capture_output=True, text=True)
    if allowed_ips_result.returncode != 0:
        return [allowed_ips_result.stderr.strip()]

    allowed_networks = set()
    for line in allowed_ips_result.stdout.splitlines():
        for value in line.split()[1:]:
            try:
                network = ipaddress.IPv4Network(value, strict=False)
            except ValueError:
                continue
            if network.prefixlen:
                allowed_networks.add(network)
    allowed_networks = sorted(allowed_networks, key=lambda network: network.prefixlen)

    for network in allowed_networks:
        covering_routes = subprocess.run(
            ['ip', '-4', 'route', 'show', 'dev', interface_name, 'match', str(network)], capture_output=True, text=True,
        ).stdout.strip()
        if covering_routes:
            continue
        # replace instead of add: the network may still be routed to another instance it was moved from
        add_result = subprocess.run(
            ['ip', '-4', 'route', 'replace', str(network), 'dev', interface_name], capture_output=True, text=True
        )
        if add_result.returncode != 0:
            errors.append(f"{network}: {add_result.stderr.strip()}")

    routes_result = subprocess.run(
        ['ip', '-o', '-4', 'route', 'show', 'dev', interface_name], capture_output=True, text=True
    )
    for route in routes_result.stdout.splitlines():
        fields = route.split()
        if not fields or 'kernel' in fields:
            continue
        try:
            route_network = ipaddress.IPv4Network(fields[0], strict=False)
        except ValueError:
            continue
        # Only routes that no allowed IP covers are removed: the interface drops their traffic anyway
        if any(route_network.subnet_of(network) for network in allowed_networks):
            continue
        delete_result = subprocess.run(
            ['ip', '-4', 'route', 'delete', str(route_network), 'dev', interface_name], capture_output=True, text=True,
        )
        if delete_result.returncode != 0:
            errors.append(f"{route_network}: {delete_result.stderr.strip()}")
    return errors


def func_reload_wireguard_interface(target: Union[str, WireGuardInstance], config_dir: str = "/etc/wireguard") -> tuple[bool, str]:
    success, message = reload_wireguard_interface(target, config_dir)
    if not success and isinstance(target, WireGuardInstance):
        # Keep the apply banner so the configuration is applied again with a restart
        target.pending_changes = True
        WireGuardInstance.objects.filter(pk=target.pk).update(pending_changes=True)
    return success, message


def reload_wireguard_interface(target: Union[str, WireGuardInstance], config_dir: str) -> tuple[bool, str]:
    """
    Reload a WireGuard interface safely using:
        wg syncconf <iface> <(wg-quick strip <conf>)

    Accepts:
        - "wg0"
        - "wg0.conf"
        - WireGuardInstance object

    Returns:
        (success: bool, message: str)
    """

    # Resolve interface name and config path
    if isinstance(target, WireGuardInstance):
        if target.hosting_worker:
            # The worker applies the new configuration on its next synchronization
            return True, f"wg{target.instance_id} runs on {target.hosting_worker} and is updated by the cluster"
        interface_name = f"wg{target.instance_id}"
        conf_filename = f"{interface_name}.conf"
    else:
        name = target.replace(".conf", "")
        interface_name = name
        conf_filename = f"{name}.conf"

    conf_path = os.path.join(config_dir, conf_filename)

    if not os.path.exists(conf_path):
        return False, f"Config file not found: {conf_path}"

    try:
        # First, run wg-quick strip to produce a clean wg-compatible config
        strip_proc = subprocess.run(
            ["wg-quick", "strip", conf_path],
            capture_output=True,
            text=True,
            check=True,
        )

        # Write stripped config to a temp file
        temp_path = f"/tmp/wgstrip_{interface_name}.conf"
        with open(temp_path, "w") as f:
            f.write(strip_proc.stdout)

        # Apply syncconf
        sync_proc = subprocess.run(
            ["wg", "syncconf", interface_name, temp_path],
            capture_output=True,
            text=True,
        )

        os.remove(temp_path)

        if sync_proc.returncode != 0:
            return False, sync_proc.stderr.strip()

        route_errors = sync_interface_routes(interface_name)
        if route_errors:
            return False, f"{interface_name} reloaded with route errors: {'; '.join(route_errors)}"

        return True, f"{interface_name} reloaded successfully"

    except subprocess.CalledProcessError as e:
        return False, e.stderr.strip() if e.stderr else str(e)
    except Exception as e:
        return False, str(e)
