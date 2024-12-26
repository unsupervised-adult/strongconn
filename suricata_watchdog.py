#!/usr/bin/env python3
import json
import time
import subprocess
import os
import re
from datetime import datetime
import ipaddress
import inotify.adapters
import sys
# =================================================================================================
# THIS SCRIPT IS PROVIDED AS IS WITH NO WARRANTY OR SUPPORT
# StrongSwan Configuration IKEv2 Gateway
# This Python script acts as a watchdog for the Suricata IDS, blocking malicious traffic
# based on classification and internal network rules.
# It monitors the eve.json log file for new entries and blacklists IP addresses
# based on entries in the classification file. When a log entry is detected and matches the classification,
# the script will blacklist the source or destination IP address based on the traffic direction,
# ie. inbound or outbound. The script will only blacklist an IP address if it is not in the internal network
# excluding IP addresses in the whitelisted_ips set in the server's nftables firewall.
# The blacklist duration is set in the configuration file as BLACKLIST_TIMEOUT=7d.
# By adjusting the Suricata YAML and classification file, you can modify the severity of classifications
# and the sensitivity of the IDS. The script will only blacklist an IP address if the classification
# is in the classifications.conf file and the IP address is not in the whitelisted_ips set.
# 
# ****Notice:
# This configuraton file and scripts are provided as is with no warranty or support
# The author is not responsible for any damage or loss caused by the use of this script
# Use at your own risk
#
# This script is designed to be used on Debian based virtualised vm only aws,vmware,proxmox etc
# =================================================================================================
# 
# this serires of scripts was created by Felix C Frank 2024
# feedback mailto:felix.c.frank@proton.me
# =================================================================================================


# Path to eve.json log file
LOG_FILE = "/var/log/suricata/eve.json"

# Path to actions log file
LOG_ACTIONS_FILE = "/var/log/suricata_watchdog_actions/actions.log"

# Path to configuration file
CONFIG_FILE = "/etc/strongconn.conf"

# Path to classification file
CLASSIFICATION_FILE = "/etc/classifications.conf"

def load_config(config_path):
    """
    Load configuration variables from a file.
    Expected format per line: KEY="value"
    Lines starting with '#' are ignored as comments.
    """
    config = {}
    try:
        with open(config_path, "r") as f:
            for line in f.read().splitlines():
                line = line.strip()
                if line and not line.startswith("#"):
                    if "=" in line:
                        key, value = line.split("=", 1)
                        config[key.strip()] = value.strip().strip('"')
    except FileNotFoundError:
        log(f"Configuration file not found: {config_path}")
    except Exception as e:
        log(f"Error loading configuration file {config_path}: {e}")
    return config

def load_classifications(classification_path):
    """
    Load and normalize classifications from a file.
    Each classification should be on a separate line.
    Returns a set of normalized classification names.
    """
    classifications = set()
    try:
        with open(classification_path, "r") as f:
            for line in f.read().splitlines():
                line = line.strip()
                if line and not line.startswith("#"):
                    normalized_name = normalize_classification(line)
                    classifications.add(normalized_name)
    except FileNotFoundError:
        log(f"Classification file not found: {classification_path}")
    except Exception as e:
        log(f"Error loading classification file {classification_path}: {e}")
    return classifications

def normalize_classification(name):
    """
    Normalize classification names by removing all non-alphanumeric characters
    and converting to lowercase. This allows matching regardless of formatting.
    """
    return re.sub(r'[^a-zA-Z0-9]', '', name).lower()

def log(message):
    """
    Log messages with a timestamp to both the console and the actions log file.
    """
    timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    log_entry = f"{timestamp} - {message}\n"
    print(log_entry, end='') 
    try:
        os.makedirs(os.path.dirname(LOG_ACTIONS_FILE), exist_ok=True)
        with open(LOG_ACTIONS_FILE, "a") as log_file:
            log_file.write(log_entry)
            log_file.flush()  
    except Exception as e:
        print(f"Failed to write to log file: {e}")

def load_nft_set(set_name):
    """
    Load IP addresses or networks from an nftables set.
    Returns a list of ipaddress objects.
    """
    try:
        result = subprocess.run(
            ["nft", "-j", "list", "set", "inet", "firewall", set_name],
            capture_output=True, text=True, check=True
        )
        data = result.stdout
        json_data = json.loads(data)

        nft_set = []

        for item in json_data.get('nftables', []):
            if 'set' in item:
                elements = item['set'].get('elem', [])
                for elem in elements:

                    if isinstance(elem, dict) and 'prefix' in elem:
                        network = elem['prefix']
                        nft_set.append(f"{network['addr']}/{network['len']}")
                    elif isinstance(elem, str):
                        nft_set.append(elem)

      
        return [ipaddress.ip_network(elem, strict=False) for elem in nft_set]

    except subprocess.CalledProcessError as e:
        stderr_output = e.stderr.strip() if e.stderr else "No error message provided."
        log(f"Failed to load nft set '{set_name}': {stderr_output}")
        return []
    except Exception as e:
        log(f"Unexpected error loading nft set '{set_name}': {e}")
        return []

def is_ip_in_set(ip, set_name):
    """
    Check if an IP address is present in a specified nftables set.
    """
    try:
        ip_addr = ipaddress.ip_address(ip)
        nft_set = load_nft_set(set_name) 
        for subnet in nft_set:
            if ip_addr in subnet:
                return True
    except ValueError:
        log(f"Invalid IP address format: {ip}")
    except Exception as e:
        log(f"Error checking set '{set_name}' for IP {ip}: {e}")
    return False

def blacklist_ip(ip, timeout):
    """
    Add an IP address to the blacklisted_ips set in nftables with a timeout.
    """
    try:

        element = f'{{ {ip} timeout {timeout} }}'
        subprocess.run([
            "nft", "add", "element", "inet", "firewall", "blacklisted_ips", element
        ], check=True)
        log(f"Successfully added IP {ip} to blacklist with timeout {timeout}.")
    except subprocess.CalledProcessError as e:
       
        stderr_output = e.stderr.strip() if e.stderr else "No error message provided."
        log(f"Failed to add IP {ip} to blacklist: {stderr_output}")
    except Exception as e:
        log(f"Unexpected error adding IP {ip} to blacklist: {e}")

def handle_log_entry(log_entry, internal_networks, blocked_classifications, debug, timeout):
    """
    Process a single log entry from eve.json.
    """
    classification_raw = log_entry.get("alert", {}).get("category", "")
    classification = normalize_classification(classification_raw)

    if debug:
        log(f"Extracted classification: '{classification_raw}' (normalized as '{classification}')")


    src_ip = log_entry.get("src_ip", "").strip()
    dest_ip = log_entry.get("dest_ip", "").strip()
    if not classification or (not src_ip and not dest_ip):
        if debug:
            log(f"Missing necessary fields in log entry: {log_entry}")
        return


    if classification not in blocked_classifications:
        if debug:
            log(f"Classification '{classification_raw}' is NOT in the block list. Skipping entry.")
        return

    try:
        src_ip_addr = ipaddress.ip_address(src_ip)
        dest_ip_addr = ipaddress.ip_address(dest_ip)

        if any(src_ip_addr in subnet for subnet in internal_networks):
            ip_to_check = dest_ip  
            direction = "outbound"
        else:
            ip_to_check = src_ip 
            direction = "inbound"
    except ValueError:
        log(f"Invalid IP address in log entry: src_ip={src_ip}, dest_ip={dest_ip}")
        return

    if not ip_to_check:
        if debug:
            log(f"No IP available for blacklisting. Skipping entry.")
        return

   
    if is_ip_in_set(ip_to_check, "whitelisted_ips"):
        if debug:
            log(f"IP {ip_to_check} is whitelisted. Skipping blacklisting.")
        return

 
    if is_ip_in_set(ip_to_check, "blacklisted_ips"):
        if debug:
            log(f"IP {ip_to_check} is already blacklisted. Skipping adding to blacklist.")
        return

    log(f"Blacklisting IP {ip_to_check} with classification '{classification_raw}' ({direction} traffic).")
    blacklist_ip(ip_to_check, timeout)

def handle_log_rotation(current_inode):
    """
    Check if the log file has been rotated by comparing inode numbers.
    Returns True if rotated, False otherwise.
    """
    try:
        new_inode = os.stat(LOG_FILE).st_ino
        if new_inode != current_inode:
            return True
    except FileNotFoundError:
        log(f"Log file {LOG_FILE} not found during rotation check.")
    except Exception as e:
        log(f"Error checking log rotation: {e}")
    return False

def monitor_log(internal_networks, blocked_classifications, debug, timeout):
    """
    Monitor the eve.json log file for new entries using inotify.
    Process each new log entry accordingly.
    """
    
    i = inotify.adapters.Inotify()
    i.add_watch(LOG_FILE)

    try:
    
        with open(LOG_FILE, "r") as f:
            f.seek(0, os.SEEK_END)  
            current_inode = os.fstat(f.fileno()).st_ino

            while True:
                events = i.event_gen(yield_nones=False, timeout_s=1)
                for event in events:
                    (_, type_names, path, filename) = event

                    if 'IN_MODIFY' in type_names:
                        if debug:
                            log(f"Detected modification event in {LOG_FILE}")

                       
                        while True:
                            line = f.readline()
                            if not line:
                                break

                            line = line.strip()
                            if debug:
                                log(f"Read line from {LOG_FILE}: {line}")

                            if not line:
                                continue

                         
                            try:
                                log_entry = json.loads(line)
                                if debug:
                                    log(f"Parsed log entry: {log_entry}")
                            except json.JSONDecodeError:
                                if debug:
                                    log(f"Failed to parse JSON line: {line}")
                                continue

                            handle_log_entry(log_entry, internal_networks, blocked_classifications, debug, timeout)

      
                if handle_log_rotation(current_inode):
                    if debug:
                        log("Log file has been rotated. Reopening the log file.")
                    f.close()
                    with open(LOG_FILE, "r") as f_new:
                        f_new.seek(0, os.SEEK_END)
                        current_inode = os.fstat(f_new.fileno()).st_ino
                        f = f_new

                time.sleep(0.1) 

    except Exception as e:
        log(f"Unexpected error in main log monitoring loop: {e}")
    finally:
        log("Suricata watchdog script terminated.")


if __name__ == "__main__":

    config = load_config(CONFIG_FILE)

   
    DEBUG = config.get("DEBUG", "false").lower() == "true"

    try:
        internal_network_str = config.get("ROUTE_SUBNETS", "").strip()
        if not internal_network_str:
            log("ROUTE_SUBNETS is not defined in the configuration file. Exiting.")
            sys.exit(1)

        internal_networks = [
            ipaddress.ip_network(subnet.strip()) 
            for subnet in internal_network_str.split(",") 
            if subnet.strip()
        ]

        if not internal_networks:
            log("No valid subnets found in ROUTE_SUBNETS. Exiting.")
            sys.exit(1)
    except ValueError as ve:
        log(f"Invalid ROUTE_SUBNETS value in config: '{config.get('ROUTE_SUBNETS')}'. Exiting.")
        sys.exit(1)
    except Exception as e:
        log(f"Error processing ROUTE_SUBNETS: {e}. Exiting.")
        sys.exit(1)


    BLOCKED_CLASSIFICATIONS = load_classifications(CLASSIFICATION_FILE)
    if not BLOCKED_CLASSIFICATIONS:
        log("No classifications loaded. Please check the classifications.conf file. Exiting.")
        sys.exit(1)

    BLACKLIST_TIMEOUT = config.get("BLACKLIST_TIMEOUT", "").strip()
    if not BLACKLIST_TIMEOUT:
        log("BLACKLIST_TIMEOUT is not defined in the configuration file. Exiting.")
        sys.exit(1)

    if not re.match(r'^\d+[smhd]$', BLACKLIST_TIMEOUT):
        log(f"Invalid BLACKLIST_TIMEOUT format: '{BLACKLIST_TIMEOUT}'. Expected formats like '24h', '1d', '30m'. Exiting.")
        sys.exit(1)

    log("Suricata watchdog script initialized and monitoring started.")


    monitor_log(internal_networks, BLOCKED_CLASSIFICATIONS, DEBUG, BLACKLIST_TIMEOUT)
