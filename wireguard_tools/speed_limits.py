"""
Per peer bandwidth limits of a WireGuard interface, applied with tc.

The limits are read from the WireGuard configuration file: each limited peer has a "# Speed limit:" comment in its
[Peer] block. Both directions are shaped with htb, one class per peer matching all of its allowed IPs:
- download (traffic that reaches the peer) on the egress of the WireGuard interface;
- upload (traffic that the peer sends) on an ifb interface that receives the ingress of the WireGuard interface.
Shaping queues the excess instead of dropping it, which keeps TCP close to the configured rate. Upload limits need
the ifb kernel module; without it only the download limits are applied and the failure is reported.

Standard library only: the cluster node agent ships an identical copy of this file.
Usage as a script: python3 speed_limits.py <interface> <config_path>
"""
import ipaddress
import subprocess
import sys

SPEED_LIMIT_COMMENT = '# Speed limit:'
LIMIT_KEYS = ('download_kbit', 'download_burst', 'upload_kbit', 'upload_burst')


def format_speed_limit_comment(settings):
    return f'{SPEED_LIMIT_COMMENT} {settings}'


def ifb_name(interface):
    """ifb interface that shapes the upload of a WireGuard interface (interface names are limited to 15 chars)."""
    return f'ifb{interface}'[:15]


def parse_speed_limits(config_content):
    """Return a list of {'networks': [...], 'download_kbit': int, ...} for each limited peer of the configuration."""
    peers = []
    current = None
    for raw_line in config_content.splitlines():
        line = raw_line.strip()
        if line.startswith('[') and line.endswith(']'):
            if current is not None:
                peers.append(current)
            current = {'networks': [], 'limits': {}} if line == '[Peer]' else None
            continue
        if current is None:
            continue
        if line.startswith(SPEED_LIMIT_COMMENT):
            for item in line[len(SPEED_LIMIT_COMMENT):].split():
                key, _, value = item.partition('=')
                if key in LIMIT_KEYS and value.isdigit() and int(value) > 0:
                    current['limits'][key] = int(value)
        elif line.split('=', 1)[0].strip() == 'AllowedIPs' and '=' in line:
            for value in line.split('=', 1)[1].split(','):
                try:
                    network = ipaddress.ip_network(value.strip(), strict=False)
                except ValueError:
                    continue
                if network.version == 4:
                    current['networks'].append(network)
    if current is not None:
        peers.append(current)

    limited_peers = []
    for peer in peers:
        limits = peer['limits']
        if not peer['networks'] or not (limits.get('download_kbit') or limits.get('upload_kbit')):
            continue
        limited_peers.append({'networks': peer['networks'], **limits})
    return limited_peers


def _filter_priority(network):
    # The most specific network is matched first, as in routing
    return 100 + 32 - network.prefixlen


def _htb_commands(device, peers, direction, match):
    """htb root with one class per peer; unclassified traffic (default 0) is sent without limits."""
    commands = [f'qdisc add dev {device} root handle 1: htb default 0']
    for index, peer in enumerate(peers, start=1):
        class_id = f'1:{index:x}'
        rate = f"{peer[f'{direction}_kbit']}kbit"
        class_command = f'class add dev {device} parent 1: classid {class_id} htb rate {rate} ceil {rate}'
        if peer.get(f'{direction}_burst'):
            burst = f"{peer[f'{direction}_burst']}b"
            class_command += f' burst {burst} cburst {burst}'
        commands.append(class_command)
        for network in peer['networks']:
            commands.append(
                f'filter add dev {device} parent 1: protocol ip prio {_filter_priority(network)} '
                f'u32 match ip {match} {network} flowid {class_id}'
            )
    return commands


def build_tc_commands(interface, limited_peers, upload=True):
    """tc batch commands that install the limits on a clean interface (and on a clean ifb for the upload)."""
    commands = []
    download_peers = [peer for peer in limited_peers if peer.get('download_kbit')]
    upload_peers = [peer for peer in limited_peers if peer.get('upload_kbit')] if upload else []

    if download_peers:
        commands += _htb_commands(interface, download_peers, 'download', 'dst')
    if upload_peers:
        ifb = ifb_name(interface)
        commands.append(f'qdisc add dev {interface} handle ffff: ingress')
        # Only the traffic of limited peers goes through the ifb; the rest is not touched
        for peer in upload_peers:
            for network in peer['networks']:
                commands.append(
                    f'filter add dev {interface} parent ffff: protocol ip prio {_filter_priority(network)} '
                    f'u32 match ip src {network} action mirred egress redirect dev {ifb}'
                )
        commands += _htb_commands(ifb, upload_peers, 'upload', 'src')
    return commands


def remove_speed_limits(interface, run=None):
    """Remove the limits of an interface and its ifb. Missing qdiscs and devices are not an error."""
    run = run or subprocess.run
    for parent in ('root', 'ingress'):
        run(['tc', 'qdisc', 'del', 'dev', interface, parent], capture_output=True, text=True)
    run(['ip', 'link', 'delete', ifb_name(interface)], capture_output=True, text=True)


def _prepare_ifb(interface, run):
    """Create (or reuse) the ifb of an interface with a clean root. Returns an error message or ''."""
    ifb = ifb_name(interface)
    result = run(['ip', 'link', 'add', ifb, 'type', 'ifb'], capture_output=True, text=True)
    if result.returncode != 0 and 'exists' not in (result.stderr or '').lower():
        return f'upload limits need the ifb kernel module ({(result.stderr or "").strip() or "ifb not available"})'
    run(['tc', 'qdisc', 'del', 'dev', ifb, 'root'], capture_output=True, text=True)
    # The default queue of an ifb (32 packets) is too short for shaped traffic
    result = run(['ip', 'link', 'set', ifb, 'up', 'txqueuelen', '1000'], capture_output=True, text=True)
    if result.returncode != 0:
        return f'{ifb}: {(result.stderr or "").strip()}'
    return ''


def apply_speed_limits(interface, config_path, run=None):
    """Replace the limits of a running interface with the ones of its configuration. Returns the errors found."""
    run = run or subprocess.run
    try:
        with open(config_path) as config_file:
            limited_peers = parse_speed_limits(config_file.read())
    except OSError as error:
        return [f'{config_path}: {error}']

    errors = []
    for parent in ('root', 'ingress'):
        run(['tc', 'qdisc', 'del', 'dev', interface, parent], capture_output=True, text=True)

    upload = any(peer.get('upload_kbit') for peer in limited_peers)
    if upload:
        ifb_error = _prepare_ifb(interface, run)
        if ifb_error:
            # Download limits do not depend on the ifb and are still applied
            errors.append(ifb_error)
            upload = False
    else:
        run(['ip', 'link', 'delete', ifb_name(interface)], capture_output=True, text=True)

    commands = build_tc_commands(interface, limited_peers, upload=upload)
    if not commands:
        return errors
    result = run(['tc', '-batch', '-'], input='\n'.join(commands) + '\n', capture_output=True, text=True)
    if result.returncode != 0:
        # Do not leave a partial set of limits behind
        remove_speed_limits(interface, run)
        errors.append((result.stderr or result.stdout).strip() or f'tc exited with status {result.returncode}')
    return errors


if __name__ == '__main__':
    if len(sys.argv) != 3:
        print(f'Usage: {sys.argv[0]} <interface> <config_path>', file=sys.stderr)
        sys.exit(2)
    errors = apply_speed_limits(sys.argv[1], sys.argv[2])
    for error in errors:
        print(f'{sys.argv[1]}: speed limits not fully applied: {error}', file=sys.stderr)
    sys.exit(1 if errors else 0)
