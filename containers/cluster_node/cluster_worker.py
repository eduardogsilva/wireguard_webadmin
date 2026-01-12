import glob
import logging
import os
import subprocess
import time
from typing import Dict, Any

import requests

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)

# Constants
MASTER_SERVER_ADDRESS = os.environ.get('MASTER_SERVER_ADDRESS')
TOKEN = os.environ.get('TOKEN')
WIREGUARD_DIR = '/etc/wireguard'
DNS_DIR = '/etc/dnsmasq'
WORKER_VERSION = 10
REQUEST_TIMEOUT = 10

class ClusterWorker:
    def __init__(self):
        self.config_version = 0
        self.dns_version = self.get_local_dns_version()
        self.should_run = True
        self.session = requests.Session()
        
        if not MASTER_SERVER_ADDRESS or not TOKEN:
            logger.error("MASTER_SERVER_ADDRESS or TOKEN not set")
            self.should_run = False
            
        self.base_url = f"https://{MASTER_SERVER_ADDRESS}/api/cluster"
        # Validate URL scheme
        if not MASTER_SERVER_ADDRESS.startswith(('http://', 'https://')):
             self.base_url = f"https://{MASTER_SERVER_ADDRESS}/api/cluster"
        else:
             self.base_url = f"{MASTER_SERVER_ADDRESS}/api/cluster"


    def func_process_wireguard_status(self) -> Dict[str, Any]:
        command = "wg show all dump"

        process = subprocess.Popen(command, shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
        stdout, stderr = process.communicate()

        if process.returncode != 0:
            return {"message": stderr, "status": "error"}

        data: Dict[str, Dict[str, Dict[str, Any]]] = {}

        # wg dump format is tab-separated.
        # There are two kinds of lines:
        # - Interface line: interface \t private_key \t public_key \t listen_port \t fwmark
        # - Peer line: interface \t peer_public_key \t preshared_key \t endpoint \t allowed_ips \t latest_handshake \t transfer_rx \t transfer_tx \t persistent_keepalive
        for line in stdout.strip().split("\n"):
            parts = line.split("\t")
            if len(parts) < 5:
                continue

            interface = parts[0]

            # Peer lines are expected to have at least 9 fields
            if len(parts) < 9:
                # interface line, ignore
                continue

            peer_public_key = parts[1]
            endpoint = parts[3]
            allowed_ips_raw = parts[4]
            latest_handshake = parts[5]
            transfer_rx = parts[6]
            transfer_tx = parts[7]

            if interface not in data:
                data[interface] = {}

            data[interface][peer_public_key] = {
                "allowed-ips": [ip for ip in allowed_ips_raw.split(",") if ip] if allowed_ips_raw else [],
                "latest-handshakes": latest_handshake or "",
                "transfer": {"tx": int(transfer_tx or 0), "rx": int(transfer_rx or 0)},
                "endpoints": endpoint or "",
            }

        return data


    def cleanup_wireguard(self):
        logger.info("Cleaning up WireGuard configuration...")
        # Stop all wireguard interfaces
        try:
            files = glob.glob(f"{WIREGUARD_DIR}/*.conf")
            for f in files:
                interface = os.path.basename(f).replace('.conf', '')
                subprocess.run(['wg-quick', 'down', interface], capture_output=True)
        except Exception as e:
            logger.error(f"Error stopping wireguard interfaces: {e}")

        # Remove files
        try:
            for f in glob.glob(f"{WIREGUARD_DIR}/*"):
                os.remove(f)
        except Exception as e:
            logger.error(f"Error cleaning directory: {e}")

        try:
            subprocess.run(['iptables', '-t', 'nat', '-F', 'WGWADM_POSTROUTING'], capture_output=True)
            subprocess.run(['iptables', '-t', 'nat', '-F', 'WGWADM_PREROUTING'], capture_output=True)
            subprocess.run(['iptables', '-t', 'filter', '-F', 'WGWADM_FORWARD'], capture_output=True)
        except Exception as e:
            logger.error(f"Error flushing firewall: {e}")

    def get_local_dns_version(self):
        try:
            version_file = os.path.join(DNS_DIR, 'config_version.conf')
            if os.path.exists(version_file):
                with open(version_file, 'r') as f:
                    for line in f:
                        if line.startswith('DNS_VERSION='):
                            return int(line.strip().split('=')[1])
        except Exception as e:
            logger.error(f"Error reading DNS version: {e}")
        return 0

    def get_status(self):
        params = {
            'token': TOKEN,
            'worker_config_version': self.config_version,
            'worker_dns_version': self.dns_version,
            'worker_version': WORKER_VERSION
        }
        logger.info(f"Requesting status from Master... (Config Version: {self.config_version}, DNS Version: {self.dns_version}, Worker Version: {WORKER_VERSION})")
        try:
            response = self.session.get(f"{self.base_url}/status/", params=params, timeout=REQUEST_TIMEOUT)
            logger.info(f"Status response received. HTTP Code: {response.status_code}")
            return response
        except requests.RequestException as e:
            logger.error(f"Connection error while getting status: {e}")
            return None

    def download_configs(self):
        params = {
            'token': TOKEN,
            'worker_config_version': self.config_version,
            'worker_dns_version': self.dns_version,
            'worker_version': WORKER_VERSION
        }
        try:
            response = self.session.get(f"{self.base_url}/worker/get_config_files/", params=params, timeout=REQUEST_TIMEOUT)
            if response.status_code == 200:
                data = response.json()
                if data.get('status') == 'success':
                    return data
            return None
        except requests.RequestException as e:
            logger.error(f"Error downloading configs: {e}")
            return None

    def download_dns_config(self):
        params = {
            'token': TOKEN,
            'worker_config_version': self.config_version,
            'worker_dns_version': self.dns_version,
            'worker_version': WORKER_VERSION
        }
        try:
            logger.info(f"Downloading DNS config... (Current Version: {self.dns_version})")
            response = self.session.get(f"{self.base_url}/worker/get_dnsmasq_config/", params=params, timeout=REQUEST_TIMEOUT)
            if response.status_code == 200:
                tar_path = 'dnsmasq_config.tar.gz'
                with open(tar_path, 'wb') as f:
                    f.write(response.content)
                
                logger.info("Extracting DNS config...")
                if not os.path.exists(DNS_DIR):
                    os.makedirs(DNS_DIR, exist_ok=True)
                    
                subprocess.run(['tar', 'xvfz', tar_path, '-C', DNS_DIR], check=True, capture_output=True)
                if os.path.exists(tar_path):
                    os.remove(tar_path)
                
                # Update version
                self.dns_version = self.get_local_dns_version()
                logger.info(f"DNS config updated (New Version: {self.dns_version})")
                return True
            else:
                logger.error(f"Failed to download DNS config. Status: {response.status_code}")
                return False
        except Exception as e:
            logger.error(f"Error updating DNS config: {e}")
            return False

    def send_ping(self):
        params = {
            'token': TOKEN,
            'worker_config_version': self.config_version,
            'worker_dns_version': self.dns_version,
            'worker_version': WORKER_VERSION
        }
        try:
            logger.info("Sending ping to Master...")
            self.session.get(f"{self.base_url}/worker/ping/", params=params, timeout=REQUEST_TIMEOUT)
        except Exception as e:
            logger.error(f"Error sending ping: {e}")

    def apply_configs(self, data):
        logger.info("Applying new configurations...")
        files = data.get('files', {})
        cluster_settings = data.get('cluster_settings', {})
        new_config_version = cluster_settings.get('config_version', 0)

        # 1. Stop existing interfaces
        self.cleanup_wireguard()

        # 2. Write new files
        for filename, content in files.items():
            if filename == 'wg-firewall.sh' and isinstance(content, str):
                content = content.replace('wireguard-webadmin-dns', 'cluster-node-dns')
            filepath = os.path.join(WIREGUARD_DIR, filename)
            with open(filepath, 'w') as f:
                f.write(content)
            
            if filename == 'wg-firewall.sh':
                os.chmod(filepath, 0o755)

        # Start interfaces
        conf_files = glob.glob(f"{WIREGUARD_DIR}/*.conf")
        for conf in conf_files:
            interface = os.path.basename(conf).replace('.conf', '')
            logger.info(f"Starting WireGuard interface: {interface}")
            try:
                subprocess.run(['wg-quick', 'up', interface], check=True, capture_output=True)
            except subprocess.CalledProcessError as e:
                logger.error(f"Failed to start {interface}: {e.stderr.decode()}")

        # 4. Update config version
        self.config_version = new_config_version
        logger.info(f"Configuration updated to version {self.config_version}")

    def send_stats(self):
        try:
            stats = self.func_process_wireguard_status()
            params = {
                'token': TOKEN,
                'worker_config_version': self.config_version,
                'worker_dns_version': self.dns_version,
                'worker_version': WORKER_VERSION
            }
            logger.info("Sending WireGuard stats to Master...")
            response = self.session.post(f"{self.base_url}/worker/submit_wireguard_stats/", json=stats, params=params, timeout=REQUEST_TIMEOUT)
            
            if response.status_code == 200:
                logger.info("Stats sent successfully.")
                return True
            else:
                logger.error(f"Failed to send stats. Status: {response.status_code}")
                return False
        except Exception as e:
            logger.error(f"Error sending stats: {e}")
            return False

    def run(self):
        if not self.should_run:
            return

        logger.info("Cluster Worker starting...")
        
        # Initial cleanup
        self.cleanup_wireguard()

        last_config_check = 0
        last_stats_send = 0
        stats_sync_interval = 60 # Default initial value

        while True:
            current_time = time.time()
            
            # Check Config (Fixed 60s interval)
            if current_time - last_config_check >= 60:
                try:
                    response = self.get_status()
                    last_config_check = time.time()
                    
                    if response is not None:
                        if response.status_code == 403:
                            logger.error("Received 403 Forbidden (Token invalid/deleted). Deactivating WireGuard and stopping requests permanently.")
                            self.cleanup_wireguard()
                            self.config_version = 0
                            self.should_run = False
                            break

                        if response.status_code == 400:
                            logger.warning("Received 400 Bad Request (Worker suspended or error). Deactivating WireGuard and Firewall, but will keep retrying...")
                            self.cleanup_wireguard()
                            self.config_version = 0

                        if response.status_code == 200:
                            data = response.json()
                            
                            # Update stats interval from master settings
                            cluster_settings = data.get('cluster_settings', {})
                            stats_sync_interval = cluster_settings.get('stats_sync_interval', 60)

                            remote_config_version = cluster_settings.get('config_version', 0)
                            
                            # Check WireGuard Config
                            updated = False
                            if int(remote_config_version) != self.config_version:
                                logger.info(f"Config version mismatch (Local: {self.config_version}, Remote: {remote_config_version}). Updating...")
                                config_data = self.download_configs()
                                if config_data:
                                    self.apply_configs(config_data)
                                    self.send_ping()
                                    updated = True
                                else:
                                    logger.error("Failed to download config files.")
                            
                            # Check DNS Config
                            remote_dns_version = int(cluster_settings.get('dns_version', 0))
                            if not updated and remote_dns_version != self.dns_version:
                                logger.info(f"DNS version mismatch (Local: {self.dns_version}, Remote: {remote_dns_version}). Updating...")
                                if self.download_dns_config():
                                    self.send_ping()
                                    updated = True

                            if not updated and int(remote_config_version) == self.config_version and remote_dns_version == self.dns_version:
                                logger.info(f"No changes detected. Configuration is up to date (WG: {self.config_version}, DNS: {self.dns_version}).")

                except Exception as e:
                    logger.error(f"Unexpected error in config check loop: {e}")

            # Check Stats Sync
            if current_time - last_stats_send >= stats_sync_interval:
                self.send_stats()
                last_stats_send = time.time()

            # Sleep briefly to be responsive but not busy loop
            time.sleep(1)

        # Final loop state if 403 was received
        while not self.should_run:
            logger.info("Worker disabled due to 403 Forbidden. WireGuard is off.")
            time.sleep(60)

if __name__ == "__main__":
    worker = ClusterWorker()
    worker.run()
