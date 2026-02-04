import os
import subprocess
from typing import Union

from wireguard.models import WireGuardInstance


def func_reload_wireguard_interface(target: Union[str, WireGuardInstance], config_dir: str = "/etc/wireguard") -> tuple[bool, str]:
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

        return True, f"{interface_name} reloaded successfully"

    except subprocess.CalledProcessError as e:
        return False, e.stderr.strip() if e.stderr else str(e)
    except Exception as e:
        return False, str(e)
