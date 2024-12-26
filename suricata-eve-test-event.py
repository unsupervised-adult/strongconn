import json
import socket
import os
from datetime import datetime
# =================================================================================================
# THIS SCRIPT IS PROVIDED AS IS WITH NO WARRANTY OR SUPPORT
# suricata-eve-test-event.py
# This file is test script to append a test event to the eve.json file
# handy for testing suricata rules and eve.json configuration
# 
# Notice:
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
# Function to get the current timestamp in the required format
def get_current_timestamp():
    return datetime.now().strftime("%Y-%m-%dT%H:%M:%S.%f+0000")[:-3]

# Function to get local IP using socket, no external dependencies
def get_local_ip():
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.connect(("8.8.8.8", 80))
        IP = s.getsockname()[0]
        s.close()
    except Exception as e:
        print(f"Error getting local IP address: {e}")
        IP = "127.0.0.1"
    return IP

# Function to append a new entry to the eve.json file
def append_to_json(file_path, entry):
    try:
        # Convert the entry to a JSON string without newlines or indentation
        json_entry = json.dumps(entry)


        # Open the file in append mode
        with open(file_path, 'a') as file:
            file.write(json_entry + '\n')
        

    except Exception as e:
        print(f"Error appending to JSON file: {e}")

# Prompt user for source IP
source_ip = input("Enter the source IP address: ")

# Automatically determine the local IP address for the destination
local_ip = get_local_ip()

# Define the alert event with dynamic details
test_event = {
    "timestamp": get_current_timestamp(),
    "flow_id": 614359979370110,
    "in_iface": "default",
    "event_type": "alert",
    "src_ip": source_ip,
    "src_port": 54569,
    "dest_ip": local_ip,
    "dest_port": 500,
    "proto": "UDP",
    "metadata": {
        "flowbits": ["ET.Evil", "ET.DshieldIP"]
    },
    "alert": {
        "action": "allowed",
        "gid": 1,
        "signature_id": 2403328,
        "rev": 96097,
        "signature": "ET CINS Active Threat Intelligence Poor Reputation IP group 29",
        "category": "Misc Attack",
        "severity": 2,
        "metadata": {
            "affected_product": ["Any"],
            "attack_target": ["Any"],
            "created_at": [get_current_timestamp()],
            "deployment": ["Perimeter"],
            "signature_severity": ["Major"],
            "tag": ["CINS"],
            "updated_at": [get_current_timestamp()]
        }
    },
    "app_proto": "failed",
    "flow": {
        "pkts_toserver": 1,
        "pkts_toclient": 0,
        "bytes_toserver": 1290,
        "bytes_toclient": 0,
        "start": get_current_timestamp()
    }
}

file_path = '/var/log/suricata/eve.json'

append_to_json(file_path, test_event)
print(f"Appended test event to {file_path} for source IP {source_ip} and destination IP {local_ip}.")
