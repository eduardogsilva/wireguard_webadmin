#!/usr/bin/env python3
import os
import sys
import uuid
import base64
import time
import requests
import subprocess

# Global variables
DEBUG = True
API_ADDRESS = "http://wireguard-webadmin:8000"

# Base directory for storing RRD files
RRD_DATA_PATH = "/rrd_data"
RRD_PEERS_PATH = os.path.join(RRD_DATA_PATH, "peers")
RRD_WGINSTANCES_PATH = os.path.join(RRD_DATA_PATH, "wginstances")


def debug_log(message):
    """
    Prints a debug message with a timestamp if DEBUG is enabled.
    Timestamp format is similar to syslog (e.g. "Mar 10 14:55:02").
    """
    if DEBUG:
        timestamp = time.strftime("%b %d %H:%M:%S")
        print(f"{timestamp} - DEBUG - {message}")


def get_api_key():
    """
    Reads the API key from a file and validates it as a UUID.
    Returns the API key as a string if valid, otherwise returns None.
    """
    api_key = None
    api_file_path = "/app_secrets/rrdtool_key"

    if os.path.exists(api_file_path) and os.path.isfile(api_file_path):
        with open(api_file_path, 'r') as file:
            key_content = file.read().strip()
            try:
                uuid_obj = uuid.UUID(key_content)
                if str(uuid_obj) == key_content:
                    api_key = str(uuid_obj)
            except Exception as e:
                debug_log(f"Error validating API key: {e}")
    return api_key


def create_peer_rrd(rrd_file):
    """
    Creates an RRD file for a peer with 3 data sources:
      - tx: COUNTER
      - rx: COUNTER
      - status: GAUGE
    """
    cmd = [
        "rrdtool", "create", rrd_file,
        "--step", "300",
        "DS:tx:DERIVE:600:0:U",
        "DS:rx:DERIVE:600:0:U",
        "DS:status:GAUGE:600:0:1",
        "RRA:AVERAGE:0.5:1:1440",
        "RRA:AVERAGE:0.5:6:700",
        "RRA:AVERAGE:0.5:24:775",
        "RRA:AVERAGE:0.5:288:797"
    ]
    try:
        subprocess.run(cmd, check=True)
        debug_log(f"Created peer RRD file: {rrd_file}")
    except subprocess.CalledProcessError as e:
        debug_log(f"Error creating peer RRD file: {rrd_file} {e}")


def create_instance_rrd(rrd_file):
    """
    Creates an RRD file for a wireguard instance with 2 data sources:
      - tx: COUNTER
      - rx: COUNTER
    """
    cmd = [
        "rrdtool", "create", rrd_file,
        "--step", "300",
        "DS:tx:DERIVE:600:0:U",
        "DS:rx:DERIVE:600:0:U",
        "RRA:AVERAGE:0.5:1:1440",
        "RRA:AVERAGE:0.5:6:700",
        "RRA:AVERAGE:0.5:24:775",
        "RRA:AVERAGE:0.5:288:797"
    ]
    try:
        subprocess.run(cmd, check=True)
        debug_log(f"Created instance RRD file: {rrd_file}")
    except subprocess.CalledProcessError as e:
        debug_log(f"Error creating instance RRD file: {rrd_file} {e}")


def process_peer(peer_key, peer_data):
    """
    Processes a single peer:
      - Converts the peer key to a URL-safe base64 string (removing any '=' characters)
      - Constructs the RRD file path for the peer (stored in RRD_PEERS_PATH)
      - Extracts the transfer data (tx and rx) from the peer data
      - Determines host status (1 for online, 0 for offline) based on the latest-handshakes value
      - Creates the RRD file if it does not exist
      - Executes the rrdtool command to update the RRD database with tx, rx, and status
    """
    # Convert peer_key to URL-safe base64 and remove '=' characters
    b64_peer = base64.urlsafe_b64encode(peer_key.encode()).decode().replace("=", "")
    # Define the peer RRD file path
    rrd_file = os.path.join(RRD_PEERS_PATH, f"{b64_peer}.rrd")

    # Create the RRD file if it doesn't exist
    if not os.path.exists(rrd_file):
        create_peer_rrd(rrd_file)

    # Extract transfer data (tx and rx)
    tx = peer_data.get("transfer", {}).get("tx", 0)
    rx = peer_data.get("transfer", {}).get("rx", 0)

    # Determine host status based on latest-handshakes.
    # Host is offline (0) if latest-handshakes is "0" or if more than 5 minutes (300s) have passed.
    latest_handshake = peer_data.get("latest-handshakes", "0")
    try:
        last_time = int(latest_handshake)
    except ValueError:
        last_time = 0

    current_time = int(time.time())
    status = 0 if (last_time == 0 or (current_time - last_time) > 300) else 1

    # Build the update command for rrdtool (syntax: "N:<tx>:<rx>:<status>")
    update_str = f"N:{tx}:{rx}:{status}"
    cmd = ["rrdtool", "update", rrd_file, update_str]

    debug_log("Executing peer update command: " + " ".join(cmd))

    try:
        subprocess.run(cmd, check=True)
    except subprocess.CalledProcessError as e:
        debug_log(f"Error updating RRD for peer {peer_key} (file {rrd_file}): {e}")


def update_instance(interface, total_tx, total_rx):
    """
    Updates the RRD file for a wireguard instance corresponding to an interface.
    The file is stored in RRD_WGINSTANCES_PATH with the name <interface>.rrd.
    If the file does not exist, it will be created.
    The update command is: "N:<total_tx>:<total_rx>".
    """
    instance_file = os.path.join(RRD_WGINSTANCES_PATH, f"{interface}.rrd")

    # Create the instance RRD file if it doesn't exist
    if not os.path.exists(instance_file):
        create_instance_rrd(instance_file)

    update_str = f"N:{total_tx}:{total_rx}"
    cmd = ["rrdtool", "update", instance_file, update_str]

    debug_log("Executing instance update command: " + " ".join(cmd))

    try:
        subprocess.run(cmd, check=True)
    except subprocess.CalledProcessError as e:
        debug_log(f"Error updating RRD for instance {interface} (file {instance_file}): {e}")


def main_loop():
    """
    Main loop that:
      - Ensures the necessary directories exist
      - Retrieves the API key (terminating the script if invalid)
      - Waits 30 seconds before the first query
      - Queries the wireguard status API every 5 minutes
      - Processes each peer using process_peer()
      - Aggregates total tx and rx per interface and updates the corresponding instance RRD
      - Waits until 5 minutes have passed since the beginning of the loop before restarting
    """
    # Ensure directories exist
    os.makedirs(RRD_PEERS_PATH, exist_ok=True)
    os.makedirs(RRD_WGINSTANCES_PATH, exist_ok=True)

    # Retrieve API key before entering the loop; exit if invalid.
    api_key = get_api_key()
    if not api_key:
        print("API key not found or invalid. Exiting.")
        sys.exit(1)

    debug_log("Waiting 30 seconds before first query...")
    time.sleep(30)

    while True:
        loop_start = time.time()
        # Refresh the API key on every iteration in case the file changes
        api_key = get_api_key()
        if not api_key:
            print("API key not found or invalid. Exiting.")
            sys.exit(1)

        # Build the URL for the API call
        url = f"{API_ADDRESS}/api/wireguard_status/?rrdkey={api_key}"
        debug_log("Querying API at: " + url)
        try:
            response = requests.get(url, timeout=10)
            response.raise_for_status()
            data = response.json()
        except Exception as e:
            debug_log("Error fetching or parsing API data: " + str(e))
            time.sleep(30)
            continue

        # Process each interface and its peers, aggregate tx and rx for the interface
        for interface, peers in data.items():
            debug_log(f"Processing interface: {interface}")
            total_tx = 0
            total_rx = 0
            for peer_key, peer_info in peers.items():
                process_peer(peer_key, peer_info)
                # Sum the tx and rx values for this interface
                tx = peer_info.get("transfer", {}).get("tx", 0)
                rx = peer_info.get("transfer", {}).get("rx", 0)
                total_tx += tx
                total_rx += rx

            # Update the RRD for the wireguard instance with aggregated values
            update_instance(interface, total_tx, total_rx)

        # Calculate elapsed time and wait the remaining time to complete 5 minutes
        elapsed = time.time() - loop_start
        sleep_time = max(300 - elapsed, 0)
        debug_log(f"Waiting {sleep_time:.2f} seconds until next execution.")
        time.sleep(sleep_time)


if __name__ == '__main__':
    main_loop()
