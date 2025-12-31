import glob
import logging
import os
import subprocess
import time

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
WORKER_VERSION = 10
REQUEST_TIMEOUT = 10

class ClusterWorker:
    def __init__(self):
        self.config_version = 0
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

    def get_status(self):
        params = {
            'token': TOKEN,
            'worker_config_version': self.config_version,
            'worker_version': WORKER_VERSION
        }
        logger.info(f"Requesting status from Master... (Config Version: {self.config_version}, Worker Version: {WORKER_VERSION})")
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

    def apply_configs(self, data):
        logger.info("Applying new configurations...")
        files = data.get('files', {})
        cluster_settings = data.get('cluster_settings', {})
        new_config_version = cluster_settings.get('config_version', 0)

        # 1. Stop existing interfaces
        self.cleanup_wireguard()

        # 2. Write new files
        for filename, content in files.items():
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

    def run(self):
        if not self.should_run:
            return

        logger.info("Cluster Worker starting...")
        
        # Initial cleanup
        self.cleanup_wireguard()

        while True:
            try:
                response = self.get_status()
                
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
                        remote_config_version = data.get('cluster_settings', {}).get('config_version', 0)
                        
                        if remote_config_version != self.config_version:
                            logger.info(f"Config version mismatch (Local: {self.config_version}, Remote: {remote_config_version}). Updating...")
                            config_data = self.download_configs()
                            if config_data:
                                self.apply_configs(config_data)
                            else:
                                logger.error("Failed to download config files.")
                        else:
                            logger.info(f"No changes detected. Configuration is up to date (Version: {self.config_version}).")

            except Exception as e:
                logger.error(f"Unexpected error in main loop: {e}")

            interval = 60
            logger.info(f"Waiting {interval} seconds for next check...")
            time.sleep(interval)

        # Final loop state if 403 was received
        while not self.should_run:
            logger.info("Worker disabled due to 403 Forbidden. WireGuard is off.")
            time.sleep(60)

if __name__ == "__main__":
    worker = ClusterWorker()
    worker.run()
