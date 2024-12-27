#!/bin/bash
# 
###################################################################################################
# StrongSwan IKEv2 Site-to-Site VPN Tunnel Management Script
###################################################################################################
# Description:
#   This script manages and configures site-to-site VPN tunnels between two StrongSwan IKEv2 
#   gateways. It provides automated setup and management of IPsec connections using IKEv2 protocol.
#
# Usage:
#   ./tunnel.sh [options]
#
# 
#
# Important Notes:
#   - Requires root/sudo privileges
#   
#   
#
# Disclaimer:
#   This script is provided as-is without warranty. Use at your own risk.
#   Author assumes no liability for any damages or losses.
#
# Author: Felix C Frank
# Email: felix.c.frank@proton.me
# Version: 0.9
# Created: 27-12-24
###################################################################################################

CONFIG_PATH="/etc/strongconn.conf"
trap 'cleanup' ERR  # Catch errors for cleanup

# Error handling function
error_exit() {
    echo "Error: $1" >&2
    exit 1
}

cleanup() {
    echo "Cleaning up due to an error or interruption..."
    tear_down_vpn
    echo "Cleanup completed."
}

load_config() {
    if [ ! -f "$CONFIG_PATH" ]; then
        echo "Configuration file not found at $CONFIG_PATH" >&2
        return 1
    fi
    source "$CONFIG_PATH"
    return 0
}

validate_parameters() {
    if [[ -z "$NAME" || -z "$REMOTE_IP" || -z "$LOCAL_SUBNET" || -z "$REMOTE_SUBNET" || -z "$ROLE" ]]; then
        echo "All parameters: NAME, REMOTE_IP, LOCAL_SUBNET, REMOTE_SUBNET, and ROLE are required." >&2
        exit 1
    fi

    # Role-specific validation
    if [[ "$ROLE" == "master" ]]; then
        # Default IF_ID to 6969 if not provided
        IF_ID="${IF_ID:-6969}"
    elif [[ "$ROLE" == "initiator" ]]; then
        # Ensure IF_ID is provided
        if [[ -z "$IF_ID" ]]; then
            echo "IF_ID is required for initiator role." >&2
            exit 1
        fi
        # Ensure MD5PASSWORD is provided
        if [[ -z "$MD5PASSWORD" ]]; then
            echo "MD5PASSWORD is required for initiator role." >&2
            exit 1
        fi
    else
        echo "Invalid role specified. Allowed roles are 'master' or 'initiator'." >&2
        exit 1
    fi
}

update_config() {
    local key=$1
    local value=$2
    local config_file="$CONFIG_PATH"

    # Check if the key exists
    if grep -q "^${key}=" "$config_file"; then
        # Key exists, update its value
        sudo sed -i "s|^${key}=.*|${key}=${value}|" "$config_file"
    else
        # Key doesn't exist, append it
        echo "${key}=${value}" | sudo tee -a "$config_file" > /dev/null
    fi
}

write_md5password_to_config() {
    local password=$1
    echo "Writing MD5PASSWORD to configuration..."
    update_config "MD5PASSWORD" "$password"
    echo "MD5PASSWORD updated in the configuration file."
}

update_tun_ifid() {
    local new_ifid=$1
    local config_file="$CONFIG_PATH"

    # Check if TUN_IFID exists
    if grep -q "^TUN_IFID=" "$config_file"; then
        # TUN_IFID exists, update its value
        sudo sed -i "s|^TUN_IFID=.*|TUN_IFID=${new_ifid}|" "$config_file"
        echo "Updated TUN_IFID to ${new_ifid} in ${config_file}."
    else
        # TUN_IFID doesn't exist, append it
        echo "TUN_IFID=${new_ifid}" | sudo tee -a "$config_file" > /dev/null
        echo "Added TUN_IFID=${new_ifid} to ${config_file}."
    fi
}

tear_down_vpn() {
    local NAME=$1
    local UPDOWN_SCRIPT="/var/lib/strongswan/updown${NAME}.sh"
    echo "Starting VPN teardown for ${NAME}..."

    # Check if updown script exists
    if [ ! -f "$UPDOWN_SCRIPT" ]; then
        echo "UpDown script not found at $UPDOWN_SCRIPT. Performing general cleanup for ${NAME}."
        
        # Flush all XFRM policies and states
        echo "Flushing all XFRM policies and states..."
        sudo ip xfrm policy flush
        sudo ip xfrm state flush

        # Remove the XFRM interface if it exists
        echo "Removing XFRM interface xfrm-${NAME} if it exists..."
        if ip link show "xfrm-${NAME}" &> /dev/null; then
            sudo ip link del "xfrm-${NAME}"
        fi
    else
        # If updown script exists, source it and perform specific cleanup
        source "$UPDOWN_SCRIPT"

        # Remove specific XFRM policies and states
        echo "Removing specific XFRM policies and states..."
        sudo ip xfrm policy del src "$LOCAL_SUBNET" dst "$REMOTE_SUBNET" dir out proto esp mode tunnel
        sudo ip xfrm policy del src "$REMOTE_SUBNET" dst "$LOCAL_SUBNET" dir in proto esp mode tunnel
        sudo ip xfrm state del src "$LOCAL_IP" dst "$REMOTE_IP" proto esp 
        sudo ip xfrm state del src "$REMOTE_IP" dst "$LOCAL_IP" proto esp 

        # Remove XFRM interface
        echo "Removing XFRM interface $XFRM_INTERFACE..."
        if ip link show "$XFRM_INTERFACE" &> /dev/null; then
            sudo ip link del "$XFRM_INTERFACE" || echo "Failed to delete XFRM interface $XFRM_INTERFACE"
        else
            echo "XFRM interface $XFRM_INTERFACE not found."
        fi
    fi

    # Remove nftables rules associated with this VPN
    echo "Removing nftables rules for ${NAME}..."
    sudo nft delete table inet vpn_${NAME} || echo "Failed to delete nftables table vpn_${NAME}"

    # Remove the specific configuration file
    local CONF_FILE="/etc/swanctl/conf.d/site-2site-${NAME}.conf"
    echo "Removing site-to-site VPN configuration file $CONF_FILE..."
    if [ -f "$CONF_FILE" ]; then
        sudo rm -f "$CONF_FILE"
    else
        echo "VPN configuration file $CONF_FILE not found."
    fi

    # Remove the updown script
    echo "Removing updown script $UPDOWN_SCRIPT..."
    sudo rm -f "$UPDOWN_SCRIPT" || echo "Failed to remove updown script $UPDOWN_SCRIPT."

    echo "VPN tear-down completed."
    swanctl --load-all
}

configure_nftables() {
    local INTERFACE_NAME=$1
    local ZONE_NAME="site-${NAME}"

    echo "Configuring nftables for VPN ${NAME}..."

    # Create a new nftables table for the VPN if it doesn't exist
    sudo nft list table inet vpn_${NAME} &> /dev/null
    if [ $? -ne 0 ]; then
        echo "Creating new nftables table: vpn_${NAME}"
        sudo nft add table inet vpn_${NAME}
    fi

    # Add base chains to the table
    sudo nft add chain inet vpn_${NAME} input { type filter hook input priority 0 \; policy drop \; }
    sudo nft add chain inet vpn_${NAME} forward { type filter hook forward priority 0 \; policy drop \; }
    sudo nft add chain inet vpn_${NAME} output { type filter hook output priority 0 \; policy accept \; }

    # Allow established and related connections
    sudo nft add rule inet vpn_${NAME} input ct state established,related accept
    sudo nft add rule inet vpn_${NAME} forward ct state established,related accept

   # Save nftables configuration to persist changes
    save_nft_config

    echo "nftables configuration completed for ${NAME}."


    echo "Nftables configuration saved and service restarted."
}

create_updown_script() {
    local NAME=$1
    local INTERFACE_NAME=$2
    local REMOTE_SUBNET=$3
    local LOCAL_SUBNET=$4
    local IF_ID=$5
    local UPDOWN_SCRIPT="/var/lib/strongswan/updown-${NAME}.sh"

    echo "Creating updown script: $UPDOWN_SCRIPT"

    sudo tee "$UPDOWN_SCRIPT" > /dev/null <<EOF
#!/bin/bash

# Function to retrieve the MD5 password from /etc/strongconn.conf
get_md5_password() {
    echo "Retrieving MD5 password from /etc/strongconn.conf."
    MD5_PASSWORD=$(grep -oP '^MD5Password=\K.*' /etc/strongconn.conf)
    if [ -z "\$MD5_PASSWORD" ]; then
        echo "Error: MD5 password not found in /etc/strongconn.conf."
        exit 1
    fi
    echo "MD5 password retrieved successfully."
}

# Function to set up the XFRM interface
setup_xfrm_interface() {
    echo "Setting up XFRM interface with if_id $IF_ID."
    if ! ip link show xfrm-$NAME &> /dev/null; then
        sudo ip link add name xfrm-$NAME type xfrm if_id $IF_ID
        sudo ip link set xfrm-$NAME up
    else
        echo "XFRM interface xfrm-$NAME already exists."
    fi
}

# Function to remove the XFRM interface
remove_xfrm_interface() {
    echo "Bringing down and removing XFRM interface."
    if ip link show xfrm-$NAME &> /dev/null; then
        sudo ip link set xfrm-$NAME down
        sudo ip link del xfrm-$NAME || true
    else
        echo "XFRM interface xfrm-$NAME does not exist."
    fi
}

# Function to add XFRM interface to FRR and assign it to a different OSPF area (e.g., area 1)
add_xfrm_to_frr() {
    get_md5_password   # Retrieve the MD5 password
    echo "Adding xfrm-$NAME to FRR, assigning to OSPF area 1, and setting it active."
    sudo vtysh -c "configure terminal" \
               -c "interface xfrm-$NAME" \
               -c "no passive-interface" \
               -c "ip ospf authentication message-digest" \
               -c "ip ospf message-digest-key 1 md5 '\$MD5_PASSWORD'" \
               -c "exit" \
               -c "router ospf" \
               -c "network $REMOTE_SUBNET area 0" \
               -c "exit"
}

# Function to remove XFRM interface from FRR
remove_xfrm_from_frr() {
    echo "Removing xfrm-$NAME from FRR."
    sudo vtysh -c "configure terminal" \
               -c "no interface xfrm-$NAME" \
               -c "exit"
}

# Main logic based on PLUTO_VERB
case "$PLUTO_VERB" in
    up-client)
        # Tunnel is going up, configure xfrm interface and add it to FRR
        echo "Tunnel is up, setting up XFRM interface."
        setup_xfrm_interface
        add_xfrm_to_frr

        # Adding nftables rules for forwarding traffic between local and remote subnets
        echo "Configuring nftables rules."
            # Allow traffic to/from the XFRM interface
            sudo nft add rule inet vpn_${NAME} input iifname "xfrm-$NAME" accept
            sudo nft add rule inet vpn_${NAME} forward iifname "xfrm-$NAME" accept
            sudo nft add rule inet vpn_${NAME} output oifname "xfrm-$NAME" accept
        for local_net in "${local_subnets[@]}"; do
            for remote_net in "${remote_subnets[@]}"; do
                sudo nft add rule inet vpn_${NAME} forward ip saddr $local_net ip daddr $remote_net accept
                sudo nft add rule inet vpn_${NAME} forward ip saddr $remote_net ip daddr $local_net accept
            done
        done
        ;;
    
    down-client)
        # Tunnel is going down, clean up XFRM interface and remove it from FRR
        echo "Tunnel is down, cleaning up XFRM interface."
        remove_xfrm_interface
        remove_xfrm_from_frr

        # Removing nftables rules for traffic
        echo "Removing nftables rules."
        for local_net in "${local_subnets[@]}"; do
            for remote_net in "${remote_subnets[@]}"; do
                sudo nft delete rule inet vpn_${NAME} forward ip saddr $local_net ip daddr $remote_net accept
                sudo nft delete rule inet vpn_${NAME} forward ip saddr $remote_net ip daddr $local_net accept
            done
        done 
                sudo nft delete rule inet vpn_${NAME} input iifname "xfrm-$NAME" accept
                sudo nft delete rule inet vpn_${NAME} forward iifname "xfrm-$NAME" accept
                sudo nft delete rule inet vpn_${NAME} output oifname "xfrm-$NAME" accept
    ;;
esac

EOF
    sudo chmod +x "$UPDOWN_SCRIPT"
    sudo chmod 700 "$UPDOWN_SCRIPT"
}

master_role() {
    echo "Configuring master role..."
    MASTER_ROUTER_ID="10.255.255.1"
    MASTER_AREA=0
    MD5_KEY=$MD5Password
    echo "Your Base64 MD5 password for OSPF: $MD5Password"

    # Start writing the OSPF configuration
    echo "router ospf" | sudo tee "/etc/frr/frr.conf"
    echo "  ospf router-id $MASTER_ROUTER_ID" | sudo tee -a "/etc/frr/frr.conf"
    
    # Adding the IP_POOL network
    echo "  network $IP_POOL area 1" | sudo tee -a "/etc/frr/frr.conf"
    
    # Adding each subnet in ROUTE_SUBNETS to the configuration
    for subnet in $ROUTE_SUBNETS; do
        echo "  network $subnet area $MASTER_AREA" | sudo tee -a "/etc/frr/frr.conf"
    done

    # Additional OSPF settings
    echo "  passive-interface default" | sudo tee -a "/etc/frr/frr.conf"
    echo "  no passive-interface lo:1" | sudo tee -a "/etc/frr/frr.conf"
    echo "  passive-interface $DEFAULT_INTERFACE" | sudo tee -a "/etc/frr/frr.conf"

    # Interface specific OSPF MD5 authentication
    echo "interface $DEFAULT_INTERFACE" | sudo tee -a "/etc/frr/frr.conf"
    echo "  ip ospf authentication message-digest" | sudo tee -a "/etc/frr/frr.conf"
    echo "  ip ospf message-digest-key 1 md5 \"$MD5_KEY\"" | sudo tee -a "/etc/frr/frr.conf"

    echo "exit" | sudo tee -a "/etc/frr/frr.conf"
    # Restart FRR service
    sudo systemctl restart frr
    echo "FRR restarted with new OSPF configuration for master"
}

set_initiator() {
    write_md5password_to_config "$MD5PASSWORD"
    echo "Configured initiator role with MD5PASSWORD: $MD5PASSWORD"
    echo "Configuring initiator role..."
    INITIATOR_AREA=2
    OSPF_ROUTER_ID="10.255.255.$INITIATOR_AREA"
    INITIATOR_LOOPBACK=$OSPF_ROUTER_ID
    MD5_KEY=$MD5PASSWORD

    echo "Configuring lo:1 interface with new IP for OSPF Router ID on initiator..."
    cat <<EOF | sudo tee -a /etc/network/interfaces
auto lo:1
iface lo:1 inet static
  address $INITIATOR_LOOPBACK
  netmask 255.255.255.255
EOF
    sudo ifup lo:1 || echo "Failed to bring up lo:1"
    echo "Initiator loopback interface lo:1 is up with IP $INITIATOR_LOOPBACK"

    echo "router ospf" | sudo tee /etc/frr/frr.conf
    echo "  ospf router-id $OSPF_ROUTER_ID" | sudo tee -a /etc/frr/frr.conf
    echo "  network $IP_POOL area $INITIATOR_AREA" | sudo tee -a /etc/frr/frr.conf
    for subnet in $ROUTE_SUBNETS; do
        echo "  network $subnet area $INITIATOR_AREA" | sudo tee -a /etc/frr/frr.conf
    done
    echo "  passive-interface default" | sudo tee -a /etc/frr/frr.conf
    echo "  no passive-interface $DEFAULT_INTERFACE" | sudo tee -a /etc/frr/frr.conf
    echo "  no passive-interface lo:1" | sudo tee -a /etc/frr/frr.conf
    echo "interface $DEFAULT_INTERFACE" | sudo tee -a /etc/frr/frr.conf
    echo "  ip ospf authentication message-digest" | sudo tee -a /etc/frr/frr.conf
    echo "  ip ospf message-digest-key 1 md5 \"$MD5_KEY\"" | sudo tee -a /etc/frr/frr.conf
    echo "exit" | sudo tee -a /etc/frr/frr.conf

    sudo systemctl restart frr || echo "Failed to restart FRR"
}


save_nft_config() {
    echo "Saving nftables configuration for persistence..."

    # Save the current nftables ruleset to /etc/nftables.conf
    sudo nft list ruleset > /etc/nftables.conf

    # Ensure the nftables service is enabled to load rules at boot
    sudo systemctl enable nftables

    # Restart the nftables service to apply and persist the configuration
    sudo systemctl restart nftables

    echo "Nftables configuration saved and service restarted."
}


save_vpn_config() {
    echo "Saving VPN config to ${CONFIG_PATH}..."
    update_config "NAME" "$NAME"
    update_config "REMOTE_IP" "$REMOTE_IP"
    update_config "LOCAL_SUBNET" "$LOCAL_SUBNET"
    update_config "REMOTE_SUBNET" "$REMOTE_SUBNET"
    update_config "REQID" "$REQID"
    update_config "IF_ID" "$IF_ID"
    update_config "XFRM_INTERFACE" "$XFRM_INTERFACE"
}

create_site_to_site_conf() {
    local REMOTE_IP=$1
    local LOCAL_SUBNET=$2
    local REMOTE_SUBNET=$3
    local IF_ID=$4
    local UPDOWN_SCRIPT="/etc/strongswan.d/updown-${NAME}.sh"
    CONNECTION_NAME="site_to_site_vpn_${NAME}"
    
    echo "Creating Site-to-Site VPN configuration in /etc/swanctl/conf.d/site-2site-${NAME}.conf"
    
    sudo tee "/etc/swanctl/conf.d/site-2site-${NAME}.conf" > /dev/null <<EOF
connections {
    $CONNECTION_NAME {
        version = 2
        proposals = aes256-sha1-modp2048, aes256-sha256-modp2048, aes256-sha384-modp2048
        encap = yes
        dpd_delay = 30s
        dpd_timeout = 300s
        local_addrs = $DEFAULT_IP
        remote_addrs = $REMOTE_IP

        local {
            auth = pubkey
            certs = /etc/swanctl/x509/server.pem
            id = $DEFAULT_IP
        }

        remote {
            auth = pubkey
            id = $REMOTE_IP
            cacerts = /etc/swanctl/x509ca/aws-ca.pem
        }

        children {
            net {
                if_id_in = $IF_ID
                if_id_out = $IF_ID
                local_ts = ${LOCAL_SUBNET}
                remote_ts = ${REMOTE_SUBNET}
                rekey_time = 28800s
                start_action = start
                mode = tunnel
                  dpd_action = restart
                esp_proposals = aes256-sha1, aes256-sha256, aes256-sha384
                updown = ${UPDOWN_SCRIPT}
            }
       }
       mobike = no
       fragmentation = yes
    }
}

secrets {
    private-key {
        id = $DEFAULT_IP
        file = /etc/swanctl/private/server-key.pem
    }
}

authorities {
    vpn-ca {
        cacert = /etc/swanctl/x509ca/ca.pem
    }
    ${NAME}-ca {
        cacert = /etc/swanctl/x509ca/${NAME}-ca.pem
    }
}
EOF

    echo "Site-to-Site VPN configuration ${CONNECTION_NAME}.conf created successfully."
}

# Main Logic
if [[ $# -lt 2 ]]; then
    echo "Usage: ./tunnel.sh <NAME> <REMOTE_IP> <LOCAL_SUBNET> <REMOTE_SUBNET> <ROLE> [IF_ID] [MD5PASSWORD]"
    echo "       ./tunnel.sh <NAME> teardown"
    exit 1
fi

NAME="$1"
ACTION="$2"

if [[ "$ACTION" == "teardown" ]]; then
    tear_down_vpn "$NAME"
else
    if [[ "$#" -lt 5 ]]; then
        echo "Usage: $0 <NAME> <REMOTE_IP> <LOCAL_SUBNET> <REMOTE_SUBNET> <ROLE> [IF_ID] [MD5PASSWORD]"
        exit 1
    fi

    # Parse arguments
    REMOTE_IP="$2"
    LOCAL_SUBNET="$3"
    REMOTE_SUBNET="$4"
    ROLE="$5"
    IF_ID="${6:-}"  
    MD5PASSWORD="${7:-}"  

    # Validate parameters
    validate_parameters "$NAME" "$REMOTE_IP" "$LOCAL_SUBNET" "$REMOTE_SUBNET" "$ROLE" "$IF_ID" "$MD5PASSWORD"
    load_config || error_exit "Failed to load configuration"
    save_vpn_config
    create_site_to_site_conf "$REMOTE_IP" "$LOCAL_SUBNET" "$REMOTE_SUBNET" "$IF_ID"
    configure_nftables "$XFRM_INTERFACE"
    create_updown_script "$NAME"

    # Role-specific logic
    if [[ "$ROLE" == "master" ]]; then
        # Default IF_ID to 6969 if not provided
        IF_ID="${IF_ID:-6969}"
        echo "Configuring master role with IF_ID=${IF_ID}..."
        master_role
    elif [[ "$ROLE" == "initiator" ]]; then
        # Validate MD5PASSWORD for initiator
        if [[ -z "$MD5PASSWORD" ]]; then
            echo "MD5PASSWORD is required for initiator role." >&2
            exit 1
        fi
        echo "Configuring initiator role with IF_ID=${IF_ID} and MD5PASSWORD=${MD5PASSWORD}..."
        set_initiator
    else
        echo "Invalid role specified. Allowed roles are 'master' or 'initiator'." >&2
        exit 1
    fi

    echo "Tunnel setup successfully."
fi
