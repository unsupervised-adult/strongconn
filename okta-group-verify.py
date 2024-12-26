#!/usr/bin/env python3
# =================================================================================================
# THIS SCRIPT IS PROVIDED AS IS WITH NO WARRANTY OR SUPPORT
# StrongSwan Configuration IKEv2 Gateway
# This file is a secondary authentication script checking for connected user changes in Okta
# this still needs work I find it occasionally disconnects users that are allowed to connect
# I have not been able to determine why yet, it may be a timing issue or a bug in the script
# not all environments have this issue.
# edit crontab to run this script every 15 minutes
# */5 * * * * /usr/local/bin/okta-group-verify.py
# let script run in dryrun mode for a few days to see if it works as expected
# then set DRY_RUN to false
# to let it run and disconnect users that are not in the okta group or are disabled
# =================================================================================================
# it also has a series of helper functions to help with maintenance and configuration
# 
# *****Notice:
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
import subprocess
import requests
import logging
import os
import sys
import re
import time
from requests.exceptions import HTTPError, RequestException
from functools import wraps

os.environ["PATH"] = "/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin"

print("Script started")

# Function to load configuration
def load_config(config_path):
    config = {}
    try:
        with open(config_path, "r") as f:
            for line in f:
                line = line.strip()
                if "=" in line and not line.startswith("#"):
                    key, value = line.split("=", 1)
                    config[key.strip()] = value.strip().strip('"').strip("'")
        print("Configuration loaded successfully.")
    except FileNotFoundError:
        print(f"Configuration file not found: {config_path}")
        sys.exit(1)
    except Exception as e:
        print(f"Error reading config file: {e}")
        sys.exit(1)
    return config

# Load configuration file
CONFIG_FILE = "/etc/strongconn.conf"
LOG_FILE = "/var/log/swanctl_user_check.log"
config = load_config(CONFIG_FILE)

# Initialize variables from configuration
DRY_RUN = config.get("DRY_RUN", "false").lower() == "true"
DEBUG = config.get("DEBUG", "false").lower() == "true"

# Setup logging
logger = logging.getLogger(__name__)
logger.setLevel(logging.DEBUG if DEBUG else logging.INFO)

if not logger.hasHandlers():
    try:
        file_handler = logging.FileHandler(LOG_FILE)
        file_handler.setLevel(logging.DEBUG)
        file_formatter = logging.Formatter("%(asctime)s - %(levelname)s - %(message)s")
        file_handler.setFormatter(file_formatter)
        logger.addHandler(file_handler)
        logger.debug("File logging configured.")
    except Exception as e:
        print(f"Failed to set up file logging: {e}")
        sys.exit(1)

    console_handler = logging.StreamHandler()
    console_handler.setLevel(logging.DEBUG if DEBUG else logging.INFO)
    console_formatter = logging.Formatter("%(asctime)s - %(levelname)s - %(message)s")
    console_handler.setFormatter(console_formatter)
    logger.addHandler(console_handler)
    logger.debug("Console logging configured.")

logger.debug(f"DEBUG mode: {DEBUG}")
logger.debug(f"DRY_RUN mode: {DRY_RUN}")

OKTA_DOMAIN = config.get("OKTA_DOMAIN", "").strip()
API_TOKEN = config.get("API_TOKEN", "").strip()
APP_ID = config.get("APP_ID", "").strip()

COA_SECRET = config.get("COA_SECRET", "").strip()
COA_SERVER = config.get("COA_SERVER", "").strip()

try:
    USER_CHECK_DELAY = float(config.get("USER_CHECK_DELAY", "5"))
except ValueError:
    logger.warning("Invalid USER_CHECK_DELAY value. Defaulting to 5 seconds.")
    USER_CHECK_DELAY = 5.0

missing_params = []
for param in ["OKTA_DOMAIN", "API_TOKEN", "APP_ID", "COA_SECRET", "COA_SERVER"]:
    if not config.get(param, "").strip():
        missing_params.append(param)

if missing_params:
    error_msg = f"Missing required configuration parameters: {', '.join(missing_params)}."
    print(error_msg)
    logger.error(error_msg)
    sys.exit(1)

# Retry decorator
def retry(max_retries=3, backoff_factor=2):
    def decorator(func):
        @wraps(func)
        def wrapper(*args, **kwargs):
            retries = 0
            delay = 1
            while retries < max_retries:
                try:
                    return func(*args, **kwargs)
                except Exception as e:
                    retries += 1
                    logger.warning(f"Retry {retries}/{max_retries} for {func.__name__} failed: {e}. Retrying in {delay}s.")
                    time.sleep(delay)
                    delay *= backoff_factor
            logger.error(f"{func.__name__} failed after {max_retries} attempts.")
            raise
        return wrapper
    return decorator

@retry(max_retries=5, backoff_factor=3)
def fetch_user_details(user_email):
    logger.debug(f"Fetching user details for {user_email}.")
    headers = {'Authorization': f'SSWS {API_TOKEN}', 'Content-Type': 'application/json'}
    params = {'filter': f'profile.email eq "{user_email}"'}
    response = requests.get(f"https://{OKTA_DOMAIN}/api/v1/users", headers=headers, params=params, timeout=10)
    response.raise_for_status()
    return response

@retry(max_retries=5, backoff_factor=3)
def check_application_assignment(user_id):
    logger.debug(f"Checking application assignment for user ID {user_id}.")
    headers = {'Authorization': f'SSWS {API_TOKEN}', 'Content-Type': 'application/json'}
    response = requests.get(f"https://{OKTA_DOMAIN}/api/v1/apps/{APP_ID}/users/{user_id}", headers=headers, timeout=10)
    response.raise_for_status()
    return response

def send_coa(assigned_ip):
    command = [
        "radclient",
        "-x",
        COA_SERVER,
        "3799",
        "coa",
        COA_SECRET,
        f"Framed-IP-Address={assigned_ip}",
    ]
    try:
        if DRY_RUN:
            logger.info(f"[DRY RUN] Would send CoA command: {' '.join(command)}")
        else:
            subprocess.run(command, check=True, capture_output=True)
            logger.info(f"CoA sent successfully for IP {assigned_ip}.")
    except subprocess.CalledProcessError as e:
        logger.error(f"Failed to send CoA for {assigned_ip}: {e.stderr.decode()}")

def remove_user_xfrm(assigned_ip):
    commands = [
        ["ip", "xfrm", "state", "delete", "src", "0.0.0.0/0", "dst", f"{assigned_ip}/32", "proto", "esp"],
        ["ip", "xfrm", "state", "delete", "src", f"{assigned_ip}/32", "dst", "0.0.0.0/0", "proto", "esp"],
    ]
    for cmd in commands:
        try:
            if DRY_RUN:
                logger.info(f"[DRY RUN] Would execute: {' '.join(cmd)}")
            else:
                subprocess.run(cmd, check=True, capture_output=True)
                logger.debug(f"Executed: {' '.join(cmd)}")
        except subprocess.CalledProcessError as e:
            logger.error(f"Command failed: {' '.join(cmd)} - {e.stderr.decode()}")

def parse_vpn_connections(vpn_output):
    connections = []
    pattern = re.compile(r"@ ([\d.]+)\[[\d]+\] EAP: '([^']+)' \[([\d.]+)\]")
    for line in vpn_output.splitlines():
        match = pattern.search(line)
        if match:
            public_ip, email, assigned_ip = match.groups()
            connections.append((assigned_ip, email, public_ip))
    return connections

def check_user_in_okta(email):
    try:
        response = fetch_user_details(email)
        if response.status_code == 200:
            user_data = response.json()
            for user in user_data:
                if email.lower() == user["profile"]["email"].lower():
                    return "AUTHORIZED" if user["status"] == "ACTIVE" else "UNAUTHORIZED"
        return "UNAUTHORIZED"
    except Exception as e:
        logger.error(f"Error checking Okta for {email}: {e}")
        return "API_ERROR"

def main():
    logger.info("Starting user verification.")
    vpn_output = subprocess.getoutput("swanctl --list-sas | grep @ | grep remote | grep 'EAP:'")
    connections = parse_vpn_connections(vpn_output)

    for assigned_ip, email, public_ip in connections:
        status = check_user_in_okta(email)
        if status == "AUTHORIZED":
            logger.info(f"User {email} is authorized. Skipping.")
        elif status == "UNAUTHORIZED":
            logger.warning(f"User {email} is unauthorized. Disconnecting.")
            send_coa(assigned_ip)
            remove_user_xfrm(assigned_ip)
        else:
            logger.error(f"API error while checking {email}. Skipping.")

if __name__ == "__main__":
    main()
