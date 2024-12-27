#!/bin/bash
#
# Script: strongconn.sh
# Location: /strongconn/strongconn.sh
#
# Description:
#   This script appears to be related to IKEv2 VPN connection management with Okta integration.
#   Additional implementation details needed for more specific documentation.
#
# Usage:
#   ./strongconn.sh -install -debug -update 
#
# Dependencies:
#   1 strongconn.conf (configuration file) installer will create if not found and allow user to edit
#     no validation is done on the values in the configuration file.
#     do not change the directorys in the configuration file unless you know what you are doing
#     you can change the okta variables post installation in the configuration file or not fill them in at all
#     just make sure all the values like ip pub ip dns etc are correct before proceeeding with the installation.
#
#   2 Okta Auth Requires Okta Radius Agent to be installed Post Installation
#     a signed valid TLS Certificate is required for Okta to function correctly
#
# Author: Felix C Frank 2024
# Version: 0.9
# Created: 27-12-24
#
# =================================================================================================
# THIS SCRIPT IS PROVIDED AS IS WITH NO WARRANTY OR SUPPORT
# The author is not responsible for any damage or loss caused by the use of this script
# Use at your own risk
# 
# This file is the main installation script for StrongSwan IKEv2 Server
# it also has a series of helper functions to help with maintenance and configuration
# 
# This script is designed to be used on Debian based virtualised vm only aws,vmware,proxmox etc
# =================================================================================================
# 
# 
# feedback mailto:felix.c.frank@proton.me
# =================================================================================================
CONFIG_PATH="/etc/strongconn.conf"
HELPER_PATH="/usr/bin"


log() {
    echo "$(date +'%Y-%m-%d %H:%M:%S') - $1"
}

error_exit() {
    echo "$(date +'%Y-%m-%d %H:%M:%S') - $1" 1>&2
    exit 1
}

    if [ ! -f "$CONFIG_PATH" ]; then
        log "Configuration file not found. Creating default configuration file..."
        cp ./strongconn.conf "$CONFIG_PATH" || error_exit "Failed to copy config to /etc"
        cp ./classifications.conf /etc/classifications.conf || error_exit "Failed to copy classifications to /etc"
        chmod 640 "$CONFIG_PATH" || error_exit "Failed to set permissions on config"
    fi
 
load_config() {
    if [ -f "$CONFIG_PATH" ]; then
        . "$CONFIG_PATH"
    else
        error_exit "Configuration file not found at $CONFIG_PATH"
    fi

  
    [ -z "$TEMP_CERT_DIR" ] && error_exit "TEMP_CERT_DIR is not set in the configuration file."
    [ -z "$CERT_DIR" ] && error_exit "CERT_DIR is not set in the configuration file."
    [ -z "$PRIVATE_DIR" ] && error_exit "PRIVATE_DIR is not set in the configuration file."
    [ -z "$CA_DIR" ] && error_exit "CA_DIR is not set in the configuration file."
    [ -z "$CRL_DIR" ] && error_exit "CRL_DIR is not set in the configuration file."
    [ -z "$SRL_DIR" ] && error_exit "SRL_DIR is not set in the configuration file."
}

function wait_for_apt_lock() {
    local retries=10
    local wait_time=5
    local count=0
    while fuser /var/lib/dpkg/lock-frontend >/dev/null 2>&1 || fuser /var/lib/dpkg/lock >/dev/null 2>&1; do
        if [ $count -ge $retries ]; then
            log "Could not acquire dpkg lock after $((retries*wait_time)) seconds. Aborting."
            return 1
        fi
        log "Another apt process is running. Waiting $wait_time seconds (-attempt $((count+1))/$retries)."
        sleep $wait_time
        count=$((count+1))
    done
    return 0
}

kernel_updates() {
    if [ "$1" = "true" ]; then
        apt-mark unhold linux-image* linux-headers*
        echo "Kernel updates via apt have been enabled."
    elif [ "$1" = "false" ]; then
        apt-mark hold linux-image* linux-headers*
        echo "Kernel updates via apt have been disabled."
    else
        echo "Invalid option. Use 'true' or 'false'."
    fi
}

install_helper(){
    if [ ! -f "$HELPER_PATH/ikpki.sh" ]; then
        echo "ikpki.sh file not found. Creating default helper file..."
    cd ~/ || error_exit "Failed to change directory to home"
    cd "$SCRIPT_DIR" || error_exit "failed to return to script dir"
    cp ./ikpki.sh /usr/bin/ikpki.sh || error_exit "failed to copy helper to /usr/bin"
    chmod 600 /usr/bin/ikpki.sh || error_exit "failed to set helper permissions"
    chmod +x /usr/bin/ikpki.sh || error_exit "failed to set  helper executable"
    fi
}

reload_swanctl() {
    log "Reloading swanctl configuration..."
    swanctl --load-all
    swanctl --load-creds
    log "swanctl configuration reloaded."
}


detect_vpn_mode() {
    if is_nat_needed; then
        VPN_MODE="NAT"
    elif is_dhcp_proxy_enabled; then
        VPN_MODE="DHCP"
    else
        VPN_MODE="ROUTED"
    fi
}


configure_dns() {

    if [ -f "$CONFIG_PATH" ]; then
        . "$CONFIG_PATH"
        echo "Configuration file loaded."
    else
        echo "Configuration file not found at $CONFIG_PATH. Exiting."
        exit 1
    fi


    if [ -z "$DNS_SERVERS" ]; then
        echo "ERROR: DNS_SERVERS variable is empty. Please specify at least one nameserver."
        exit 1
    fi

  
    echo "Received DNS servers: $DNS_SERVERS"

    dns_array=(${DNS_SERVERS//,/ })


    echo "dns_array has ${#dns_array[@]} elements:"
    for dns in "${dns_array[@]}"; do
        echo "dns_array element: '$dns'"
    done

    echo "Configuring DNS..."


    echo "# Generated by configure_dns function" | tee /etc/resolv.conf > /dev/null

  
    for dns in "${dns_array[@]}"; do
        echo "Adding nameserver: $dns"
        echo "nameserver $dns" | tee -a /etc/resolv.conf > /dev/null
    done


    if [ -s /etc/resolv.conf ]; then
        echo "DNS configuration successful. Contents of /etc/resolv.conf:"
        cat /etc/resolv.conf
    else
        echo "ERROR: Failed to update /etc/resolv.conf"
    fi

    echo "Writing /etc/hosts file with configured variables..."

  
    local hostname=$(echo "$DNS_NAME" | cut -d '.' -f 1)

    echo "$DNS_NAME" | tee /etc/hostname > /dev/null
    hostname "$DNS_NAME"


    cp /etc/hosts /etc/hosts.bak

  
    cat <<EOF | tee /etc/hosts > /dev/null
# /etc/hosts file generated by configure_dns function
127.0.0.1       localhost
127.0.1.1       $DNS_NAME $hostname

# The following lines are desirable for IPv6 capable hosts
::1             localhost ip6-localhost ip6-loopback
ff02::1         ip6-allnodes
ff02::2         ip6-allrouters

# Custom host entries
$DEFAULT_IP     $DNS_NAME $hostname
$PUBLIC_IP      $DNS_NAME $hostname
EOF

    echo "Hosts file updated successfully."
}


check_dns_resolution() {
    local test_domain="google.com"
    log "checking DNS resolution..."
    if ! ping -c 1 "$test_domain" &> /dev/null; then
        error_exit "DNS resolution check failed. Please check your DNS is correctly configured."
    fi
}

check_root() {
    if [ "$(id -u)" != 0 ]; then
        error_exit "Script must be run as root. Try 'bash $0'."
    fi
}


check_os() {
    log "Checking OS compatibility..."
    if [ -f /etc/os-release ]; then
        . /etc/os-release  
        if [[ "$ID" != "debian" && "$ID" != "ubuntu" ]]; then
            log "Unsupported OS. This script only supports Debian-based systems."
            exit 1  
        fi
    else
        error_exit "Unable to determine OS type. This script only supports Debian-based systems."
    fi
    log "OS check completed. System is compatible."
}

check_network() {
    log "checking network connectivity..."
    if ! ping -c 3 google.com; then
        error_exit "Network connectivity check failed. Please check you have an active internet connection."
    fi
}

check_strongswan_group() {
      echo "Setting up users and groups for StrongSwan and OCSP..."

    # Create 'strongswan' group if it doesn't exist
    if ! getent group strongswan > /dev/null; then
        echo "Creating 'strongswan' group..."
        groupadd strongswan || {
            echo "Error: Failed to create 'strongswan' group."
            exit 1
        }
    else
        echo "'strongswan' group already exists."
    fi

    # Create 'ocsp' group if it doesn't exist
    if ! getent group ocsp > /dev/null; then
        echo "Creating 'ocsp' group..."
        groupadd ocsp || {
            echo "Error: Failed to create 'ocsp' group."
            exit 1
        }
    else
        echo "'ocsp' group already exists."
    fi

    # Create 'strongswan' user if it doesn't exist
    if ! id -u strongswan > /dev/null 2>&1; then
        echo "Creating 'strongswan' user..."
        useradd -r -g strongswan -s /sbin/nologin strongswan || {
            echo "Error: Failed to create 'strongswan' user."
            exit 1
        }
    else
        echo "'strongswan' user already exists."
    fi

    # Create 'ocsp' user if it doesn't exist
    if ! id -u ocsp > /dev/null 2>&1; then
        echo "Creating 'ocsp' user..."
        useradd -r -g ocsp -s /sbin/nologin ocsp || {
            echo "Error: Failed to create 'ocsp' user."
            exit 1
        }
    else
        echo "'ocsp' user already exists."
    fi
   
}

check_charon_socket_permissions() {
    touch /var/run/charon.vici
    chown root:strongswan /var/run/charon.vici
    chmod 770 /var/run/charon.vici
}


check_and_compile_modules() {
    log "Checking required kernel modules..."

    required_modules=("af_key" "xfrm_user" "iptable_nat" "xfrm_algo" "xfrm4_tunnel" "nf_nat" "esp4" "ah4" "nf_conntrack" "nf_defrag_ipv4" "xfrm_interface" )
    missing_modules=()


    cmds=(depmod modprobe make)
    packages=(kmod kmod build-essential)

    # Update package list once
    apt-get update -y

    for i in "${!cmds[@]}"; do
        cmd="${cmds[$i]}"
        package="${packages[$i]}"
        if ! command -v "$cmd" &> /dev/null; then
            log "Command $cmd not found. Installing package $package..."
            apt-get install -y "$package"
        fi
    done

    for module in "${required_modules[@]}"; do
        if ! lsmod | grep -qw "^$module"; then
            log "Kernel module $module not loaded, attempting to load..."
            if modprobe "$module"; then
                log "Kernel module loaded successfully: $module"
            else
                log "Failed to load kernel module: $module"
                missing_modules+=("$module")
            fi
        else
            log "Kernel module already loaded: $module"
        fi

        if ! grep -qw "^$module$" /etc/modules; then
            echo "$module" | tee -a /etc/modules > /dev/null
            log "Added kernel module to /etc/modules: $module"
        else
            log "Kernel module already in /etc/modules: $module"
        fi
    done

    if [ ${#missing_modules[@]} -ne 0 ]; then
        log "Some modules are missing or failed to load, compiling the missing modules..."

        log "Installing build tools and dependencies..."
        apt-get install -y build-essential libncurses-dev bison flex libssl-dev libelf-dev bc dwarves kmod
        apt-get install -y linux-headers-"$(uname -r)"

        KERNEL_VERSION=$(uname -r)
        KERNEL_HEADERS_DIR="/usr/src/linux-headers-$KERNEL_VERSION"

        if [ ! -d "$KERNEL_HEADERS_DIR" ]; then
            log "Kernel headers directory not found: $KERNEL_HEADERS_DIR"
            exit 1
        fi

        cd "$KERNEL_HEADERS_DIR" || { log "Failed to enter kernel headers directory."; exit 1; }

        log "Preparing for module compilation..."
        make modules_prepare


        for module in "${missing_modules[@]}"; do
            case "$module" in
                af_key)
                    MODULE_PATH="net/key/af_key"
                    CONFIG_OPTION="CONFIG_NET_KEY"
                    ;;
                xfrm_user)
                    MODULE_PATH="net/xfrm"
                    CONFIG_OPTION="CONFIG_XFRM_USER"
                    ;;
                xfrm_algo)
                    MODULE_PATH="crypto/xfrm_algo"
                    CONFIG_OPTION="CONFIG_XFRM_ALGO"
                    ;;
                esp4)
                    MODULE_PATH="net/ipv4/esp4"
                    CONFIG_OPTION="CONFIG_INET_ESP"
                    ;;
                ah4)
                    MODULE_PATH="net/ipv4/ah4"
                    CONFIG_OPTION="CONFIG_INET_AH"
                    ;;
                xfrm4_tunnel)
                    MODULE_PATH="net/ipv4/xfrm4_tunnel"
                    CONFIG_OPTION="CONFIG_INET_XFRM_TUNNEL"
                    ;;
                xfrm_interface)
                    MODULE_PATH="net/xfrm/xfrm_interface"
                    CONFIG_OPTION="CONFIG_XFRM_INTERFACE"
                    ;;
                nf_nat)
                    MODULE_PATH="net/ipv4/netfilter/nf_nat"
                    CONFIG_OPTION="CONFIG_NF_NAT"
                    ;;
                nf_conntrack)
                    MODULE_PATH="net/netfilter/nf_conntrack"
                    CONFIG_OPTION="CONFIG_NF_CONNTRACK"
                    ;;
                nf_defrag_ipv4)
                    MODULE_PATH="net/ipv4/netfilter/nf_defrag_ipv4"
                    CONFIG_OPTION="CONFIG_NF_DEFRAG_IPV4"
                    ;;
                *)
                    log "No specific compilation instructions for module: $module"
                    continue
                    ;;
            esac


            sed -i "s/# $CONFIG_OPTION is not set/$CONFIG_OPTION=m/" .config
            echo "$CONFIG_OPTION=m" | tee -a .config > /dev/null

            log "Compiling module $module..."
            if make M=./"$MODULE_PATH" modules; then
                log "Module $module compiled successfully."
            else
                log "Failed to compile module: $module"
                continue
            fi

            log "Installing module $module..."
            if make M=./"$MODULE_PATH" modules_install; then
                log "Module $module installed successfully."
            else
                log "Failed to install module: $module"
                continue
            fi

            if modprobe "$module"; then
                log "Loaded kernel module after compilation: $module"
            else
                log "Failed to load kernel module after compilation: $module"
            fi
        done

        log "Running depmod to update module dependencies..."
        depmod -a
        log "depmod completed."

        cd ~ || exit
    else
        log "All required kernel modules are loaded."
    fi
}


command_exists() {
    command -v "$1" >/dev/null 2>&1
}
   
init_db() {
    log "Initializing PKI directories ..."
    source "$CONFIG_PATH"
    if [[ -z "$CA_DIR" ]] || [[ -z "$CERT_DIR" ]] || [[ -z "$TEMP_CERT_DIR" ]]; then
        error_exit "Required directories are not set in the configuration file. Aborting database initialization."
    fi
    /usr/bin/ikpki.sh check
    /usr/bin/ikpki.sh init

    log "directories initialized successfully."
}


generate_ca() {

    log "Generating self-signed CA certificate..."
    if [[ ! -f "$CONFIG_PATH" ]]; then
        error_exit "Configuration file $CONFIG_PATH not found. Aborting CA generation."
    fi
    source "$CONFIG_PATH"
    /usr/bin/ikpki.sh generate-ca || error_exit "Failed to generate CA certificate"
    log "CA certificate successfully generated."

}


generate_server() {
    log "Generating server certificate..."
    if [[ ! -f "$CONFIG_PATH" ]]; then
        error_exit "Configuration file $CONFIG_PATH not found. Aborting server certificate generation."
    fi
    source "$CONFIG_PATH"
    if [[ -z "$CA_DIR" ]] || [[ -z "$CERT_DIR" ]] || [[ -z "$TEMP_CERT_DIR" ]] || [[ -z "$COUNTRY" ]] || [[ -z "$STATE" ]] || [[ -z "$CITY" ]] || [[ -z "$ORGANIZATION" ]] || [[ -z "$ORG_UNIT" ]] || [[ -z "$CA_DURATION" ]] || [[ -z "$PFX_PASSWORD" ]] || [[ -z "$DNS_NAME" ]] || [[ -z "$PUBLIC_IP" ]]; then
        error_exit "Required variables are not set in the configuration file. Aborting server certificate generation."
    fi
    /usr/bin/ikpki.sh generate-server || error_exit "Failed to generate server certificate"
   # /usr/bin/ikpki.sh generate-custom-server || error_exit "Failed to generate testing TLS certificate"
log "Server certificates successfully generated."
}

check_ip() {
    local ip=$1
    local stat=1

    if [[ $ip =~ ^[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}$ ]]; then
        OIFS=$IFS
        IFS='.'
        ip=("$ip")
        IFS=$OIFS
        [[ ${ip[0]} -le 255 && ${ip[1]} -le 255 && \
           ${ip[2]} -le 255 && ${ip[3]} -le 255 ]]
        stat=$?
    fi
    return $stat
}

get_default_ip() {
    local default_iface
    default_iface=$(ip -4 route list 0/0 | awk '{print $5}' | head -n1)
    public_ip=$(ip -4 addr show "$default_iface" | awk '/inet/ {print $2}' | cut -d'/' -f1 | head -n1)
}

get_server_ip() {
    public_ip=${VPN_PUBLIC_IP:-''}

    log "Trying to auto discover IP of this server..."
    check_ip "$public_ip" || public_ip=$(dig @resolver1.opendns.com -t A -4 myip.opendns.com +short)
    check_ip "$public_ip" || public_ip=$(wget -t 2 -T 10 -qO- http://ipv4.icanhazip.com)
    check_ip "$public_ip" || public_ip=$(wget -t 2 -T 10 -qO- http://ip1.dynupdate.no-ip.com)

    if ! check_ip "$public_ip"; then
        error_exit "Could not detect this server's public IP. Please manually set the VPN_PUBLIC_IP variable in the configuration file."
    fi
}

install_dependencies() {
    log "Installing dependencies..."
    apt-get update -y || error_exit "Failed to update package lists."
    apt-get install -y \
        build-essential \
        libgmp-dev \
        libssl-dev \
        libcap-ng-dev \
        jq \
        libpam0g-dev \
        freeradius-utils \
        libnftables1 \
        iproute2 \
        ipcalc \
        gettext \
        nftables \
        python3-inotify \
        uuid-runtime \
        cockpit \
        util-linux \
        tmux \
        bridge-utils \
        openssl \
        libcurl4-openssl-dev \
        frr \
        frr-doc \
        libjson-c-dev \
        pkg-config \
        libsystemd-dev \
        bind9utils \
        iftop \
        tcpdump \
        libnss3-tools \
        btop \
        lsof \
        net-tools \
        chrony \
        vnstat \
        swaks \
        mailutils \
        cron \
        nmap \
        locate \
        debsums \
        traceroute \
        acl \
        ethtool \
        tree \
        acct \
        wget \
        curl\
        unzip \
        syslog-ng \
        net-tools \
        rkhunter \
        apt-transport-https \
        software-properties-common \
        dnsutils || error_exit "Failed to install dependencies."
   

       apt update
  
    log "Dependencies installed successfully."
}


compile_strongswan() {
    log "Compiling Latest Version of StrongSwan from source..."
    cd /usr/src/ || error_exit "Failed to change directory to /usr/src/."
    latest_version=$(curl -s https://download.strongswan.org/ \
        | grep -oP 'strongswan-\K[0-9]+\.[0-9]+\.[0-9]+(?=\.tar\.bz2)' \
        | sort -V | tail -1)

    if [ -z "$latest_version" ]; then
        error_exit "Failed to determine the latest StrongSwan version."
    fi
    log "Latest StrongSwan version is $latest_version"
    tarball="strongswan-$latest_version.tar.bz2"
    download_url="https://download.strongswan.org/$tarball"
    wget "$download_url" || error_exit "Failed to download StrongSwan source."
    tar xjf "$tarball" || error_exit "Failed to extract StrongSwan source."
    cd "strongswan-$latest_version" || error_exit "Failed to enter StrongSwan source directory."
     ./configure --prefix=/usr \
            --sysconfdir=/etc \
            --enable-aes \
            --enable-sha1 \
            --enable-sha2 \
            --enable-random \
            --enable-x509 \
            --enable-pubkey \
            --enable-openssl \
            --enable-gmp \
            --enable-kernel-netlink \
            --enable-socket-default \
            --enable-vici \
            --enable-updown \
            --enable-eap-identity \
            --enable-eap-md5 \
            --enable-eap-mschapv2 \
            --enable-eap-tls \
            --enable-eap-ttls \
            --enable-eap-radius \
            --enable-dhcp \
            --enable-farp \
            --enable-charon \
            --enable-systemd \
            --enable-curl \
            --enable-cmd \
            --enable-swanctl \
            --enable-curve25519 \
            --enable-files \
            --enable-lookip \
            --enable-revocation \
            --enable-constraints \
            --enable-pki \
            --enable-pem \
            --enable-pkcs8 \
            --enable-pkcs1 \
            --enable-pem \
            --enable-gcm \
            --enable-aesni \
            --with-systemdsystemunitdir=/lib/systemd/system || error_exit "Failed to configure StrongSwan."
    make || error_exit "Failed to compile StrongSwan."
    make install || error_exit "Failed to install StrongSwan."
    cd ..
    log "StrongSwan compiled and installed."
    cd ~/ || error_exit "failed "
    systemctl daemon-reload
}


setup_cockpit() {  
    log "Setting up Cockpit with 45drives repository..."

    # Ensure the directory for Cockpit extensions exists
    mkdir -p /usr/share/cockpit/strongswan

    # Download and add 45Drives repository key securely
    log "Adding 45Drives repository key..."
    wget -qO - https://repo.45drives.com/key/gpg.asc | \
        gpg --dearmor -o /usr/share/keyrings/45drives-archive-keyring.gpg || \
        error_exit "Failed to add 45Drives GPG key."

    # Add 45Drives repository source file
    log "Adding 45Drives repository..."
    cat > /etc/apt/sources.list.d/45drives.sources <<EOF
X-Repolib-Name: 45Drives
Enabled: yes
Types: deb
URIs: https://repo.45drives.com/debian
Suites: focal
Components: main
Architectures: amd64
Signed-By: /usr/share/keyrings/45drives-archive-keyring.gpg
EOF

    # Update package list and install cockpit-navigator
    log "Updating package list..."
    TMPDIR=/var/tmp apt-get update -y || error_exit "Failed to update package list."

    log "Installing cockpit-navigator..."
    TMPDIR=/var/tmp apt-get install cockpit-navigator -y || error_exit "Failed to install cockpit-navigator."

    log "Cockpit setup complete."
}

setup_frr_ospf() {
    log "Configuring loopback interface lo:1 for OSPF Router ID..."
    # Add loopback interface dynamically
    ip addr add 10.255.255.1/32 dev lo || { log "ERROR: Failed to add IP address to lo"; exit 1; }
    ip link set lo up

    # Verify the loopback interface
    if ip a show lo | grep -q "10.255.255.1"; then
        log "Loopback interface lo:1 is up"
    else
        log "ERROR: Failed to bring up loopback interface lo:1"
        exit 1
    fi

    # Generate a random Base64 MD5 password
    random_bytes=$(head -c 16 /dev/urandom | base64)
    log "Your random Base64 MD5 password: $random_bytes"

    # Enable OSPF daemon
    log "Enabling ospfd in /etc/frr/daemons..."
    if grep -q "^ospfd=" /etc/frr/daemons; then
        sed -i "s/^ospfd=.*/ospfd=yes/" /etc/frr/daemons
    else
        echo "ospfd=yes" | tee -a /etc/frr/daemons
    fi
    log "ospfd has been enabled in /etc/frr/daemons."

    # Configure OSPF in FRR
    log "Configuring OSPF in FRR..."
    cat <<EOF | tee /etc/frr/frr.conf
router ospf
  ospf router-id 10.255.255.1
  passive-interface default
  no passive-interface lo
EOF

    # Add OSPF authentication
    DEFAULT_INTERFACE=$(ip route | grep default | awk '{print $5}')
    cat <<EOF | tee -a /etc/frr/frr.conf
interface $DEFAULT_INTERFACE
  ip ospf authentication message-digest
  ip ospf message-digest-key 1 md5 "$random_bytes"
exit
EOF
    log "OSPF authentication configuration added."

    # Add subnets to OSPF configuration
    if [ "$VPN_MODE" = "NAT" ] || [ "$VPN_MODE" = "ROUTED" ]; then
        echo "  network $IP_POOL area 1" | tee -a /etc/frr/frr.conf
        log "Added $IP_POOL to OSPF configuration for area 1"
    fi

    IFS=',' read -ra SUBNETS <<< "$ROUTE_SUBNETS"
    for subnet in "${SUBNETS[@]}"; do
        echo "  network $subnet area 0" | tee -a /etc/frr/frr.conf
    done

    # Store the MD5 password in the configuration path
    echo "MD5Password=$random_bytes" | tee -a "$CONFIG_PATH"
    log "MD5 password added to $CONFIG_PATH"

    # Enable and start FRR service
    log "Enabling and starting FRR service..."
    systemctl enable frr
    if ! systemctl is-active --quiet frr; then
        log "FRR service is not running. Starting it now..."
        systemctl start frr
        sleep 5
    else
        log "FRR service is already running."
    fi

    # Restart FRR service
    systemctl restart frr
    if systemctl is-active --quiet frr; then
        log "FRR service is running."
        systemctl status frr | grep ospfd
    else
        log "ERROR: FRR service failed to start."
        exit 1
    fi

    # Check OSPF status
    log "Checking OSPF status..."
    vtysh -c "show ip ospf"

    log "FRR and OSPF setup complete."
}



configure_swanctl() {
    log "Configuring StrongSwan with swanctl..."
    mkdir -p /etc/swanctl/conf.d
    mkdir -p /etc/swanctl/x509/{cacerts,certs,private}
    mkdir -p /etc/strongswan.d/charon
    mkdir -p /var/run/charon
    chown root:strongswan /var/run/charon
    chmod 770 /var/run/charon
    touch /var/run/charon.vici
    chown root:strongswan /var/run/charon.vici
    chmod 770 /var/run/charon.vici
    mkdir -p /var/lib/strongswan
    chown root:strongswan /var/lib/strongswan
    chmod 770 /var/lib/strongswan

    cat <<EOF | tee /etc/strongswan.d/charon.conf
charon {
    dos_protection = yes
    prefer_configured_proposals = yes
    load_crls = yes
    cache_crls = yes
    group = strongswan
    
    tls {

        send_certreq_authorities = yes
    }

}
EOF

    chmod 600 /etc/strongswan.d/charon.conf

    cat <<EOF | tee /etc/strongswan.d/charon/revocation.conf
    revocation {

        enable_crl = yes
        enable_ocsp = yes
        load = yes
        # timeout = 10s

}

EOF
    chmod 600 /etc/strongswan.d/charon/revocation.conf

    cat <<EOF | tee /etc/strongswan.d/charon/eap-radius.conf
eap-radius {
    load = yes
    servers {
        okta-radius-agent {
            address = 127.0.0.1
            secret = ${RADIUS_SECRET}
            auth_port = 1812
        }
    }
        dae {
        enable = yes
        listen = 127.0.0.1  
        port = 3799
        secret = ${COA_SECRET}
    }
}

EOF
    chmod 600 /etc/strongswan.d/charon/eap-radius.conf
      
       local pool_name="main-pool"
    if [ "$VPN_MODE" = "DHCP" ]; then
        pool_name="dhcp"
    fi

    cat <<EOF | tee /etc/swanctl/swanctl.conf
pools {
    main-pool {
        addrs = ${IP_RANGE}
        dns = ${DNS_SERVERS}
    }
}

authorities {
    vpn-ca {
        cacert = /etc/swanctl/x509ca/ca.pem
        ocsp_uris = [ "http://$PUBLIC_IP/ocsp" ]
        crl_uris = [ "http://$PUBLIC_IP/crl/crl.pem" ]
    }
}
include conf.d/*.conf
EOF

    chmod 600 /etc/swanctl/swanctl.conf

 cat <<EOF | tee /etc/swanctl/conf.d/ikev2-cert.conf
connections {
    ikev2-cert {
        version = 2
        proposals = aes256-sha256-ecp256, aes256-sha256-modp2048, aes256gcm16-prfsha256-ecp256, aes128-sha256-modp2048, aes256-sha1-modp2048, aes256-sha384-modp2048, aes256-sha256-ecp384, aes256-sha384-ecp384, aes256-sha256-ecp521, aes256gcm16-sha256-ecp256
        dpd_delay = 30s
        dpd_timeout = 300s
        unique = replace
        local {
            auth = pubkey
            certs = /etc/swanctl/x509/server.pem
            id = ${PUBLIC_IP}
        }
        remote {
            auth = pubkey
            revocation = ifuri
            id = %any
    
        }
        children {
            net {
                local_ts = 0.0.0.0/0
                remote_ts = dynamic
                rekey_time = 0s
                start_action = none
                dpd_action = restart
                mode = tunnel
                esp_proposals =  aes256-sha256, aes128gcm16-modp2048, aes256gcm16-modp2048, aes128-sha256-modp2048, aes256-sha256-modp2048, aes256gcm16-ecp256, aes256gcm16       
            }
        }
        pools = $pool_name
        mobike = yes
        fragmentation = yes
    }
}
secrets {
    private-key {
        id = ${PUBLIC_IP}
        file = /etc/swanctl/private/server-key.pem
    }
}
EOF
       local dhcp="no"
    if [ "$VPN_MODE" = "DHCP" ]; then
             dhcp="yes"
    fi

    cat <<EOF | tee /etc/strongswan.conf
charon {
    load_modular = yes
 
    plugins {
        kernel-netlink {
            mtu = 1400
            mss = 1360
        }
        include strongswan.d/charon/*.conf
    }
    syslog {
        identifier = charon
    }
    start-scripts {
        creds = /usr/local/sbin/strongswan-creds
    }
    attr {
           dns = $DNS_SERVERS
    }
    eap-ttls {
            fragment_size = 1024
            include_length = yes
            max_message_count = 32
            phase2_method = pap
            phase2_piggyback = no
        }
    farp {
        load = no
    }
    dhcp {
        load = $dhcp
        server = $DEFAULT_GATEWAY
        force_server_address = no
        identity_lease = yes
        interface = $DEFAULT_INTERFACE
    }
    kernel-netlink {
        install_routes_xfrmi = yes

    }
}
include strongswan.d/*.conf
EOF
    chmod 600 /etc/strongswan.conf
    cat <<EOF | tee /usr/local/sbin/strongswan-creds
#!/bin/sh
swanctl --load-creds
EOF
    chmod +x /usr/local/sbin/strongswan-creds
    cat <<EOF | tee /etc/strongswan.d/charon-vici.conf
charon {
    vici {
        socket = unix:///var/run/charon.vici
        group = strongswan
    }
}
EOF
    cat <<EOF | tee /etc/systemd/system/swanctl-load.service > /dev/null
[Unit]
Description=Load all StrongSwan configurations using swanctl
After=ssh.service strongswan.service
Wants=ssh.service strongswan.service

[Service]
Type=oneshot
ExecStart=/usr/sbin/swanctl --load-all
RemainAfterExit=yes

[Install]
WantedBy=multi-user.target
EOF
    systemctl daemon-reload
    systemctl enable swanctl-load.service
    cat <<EOF | tee /lib/systemd/system/strongswan.service
[Unit]
Description=strongSwan IPsec IKEv1/IKEv2 daemon using swanctl
After=network.target

[Service]
Type=notify
ExecStartPre=/bin/mkdir -p /var/run/charon
ExecStartPre=/bin/chown root:strongswan /var/run/charon
ExecStartPre=/bin/chmod 770 /var/run/charon
ExecStartPre=/bin/touch /var/run/charon.vici
ExecStartPre=/bin/chown root:strongswan /var/run/charon.vici
ExecStartPre=/bin/chmod 770 /var/run/charon.vici
ExecStart=/usr/sbin/charon-systemd
Restart=on-failure
KillMode=process

[Install]
WantedBy=multi-user.target
EOF

    log "Reloading systemd configuration and starting StrongSwan service..."
    systemctl daemon-reload
    systemctl enable strongswan
    systemctl start strongswan
    systemctl start frr
    systemctl enable frr
    log "Waiting for StrongSwan service to start..."
    for i in {1..30}; do
        if [ -S /var/run/charon.vici ]; then
            log "VICI socket created successfully."
            break
        fi
        sleep 1
    done

    if [ ! -S /var/run/charon.vici ]; then
        log "ERROR: VICI socket not created after 30 seconds. check StrongSwan service status."
        systemctl status strongswan
        exit 1
    fi
    log "Reloading swanctl configuration..."
    swanctl --load-all
    if [ $? -ne 0 ]; then
        log "ERROR: Failed to load swanctl configuration. check logs for details."
        exit 1
    fi
    log "swanctl configuration reloaded."

    log "StrongSwan configuration complete swanctl."
}

setup_ocsp_responder() {
    source /etc/strongconn.conf

    # Ensure required directories exist
    log "Creating necessary directories..."
    mkdir -p "$OCSP_DIR" "$CRL_DIR" "$CA_DIR" "$PRIVATE_DIR" "$TEMP_CERT_DIR" || error_exit "Failed to create directories."
    chown root:ocsp "$OCSP_DIR" "$CRL_DIR"
    chmod 750 "$OCSP_DIR" "$CRL_DIR"

    # Check and install NGINX if not already installed
    if ! command -v nginx >/dev/null 2>&1; then
        log "NGINX not found. Installing NGINX..."
        apt-get update && apt-get install -y nginx 
    fi

    # Ensure NGINX directories exist
    log "NGINX creating configuration directories ..."
    mkdir -p /etc/nginx/sites-available /etc/nginx/sites-enabled || error_exit "Failed to create NGINX directories."


    # Generate OCSP responder key and certificate if missing
    if [[ ! -f "$OCSP_KEY" || ! -f "$OCSP_CERT" ]]; then
        log "Generating OCSP responder key and certificate..."
        ./ikpki.sh generate-ocsp-cert || error_exit "Failed to generate OCSP certificate."
    else
        log "OCSP key and certificate already exist."
    fi

    # Ensure CA certificate exists
    if [[ ! -f "$CA_CERT" ]]; then
        error_exit "CA certificate is missing: $CA_CERT"
    fi

    log "Linking CRL file for NGINX..."
    mkdir -p "$OCSP_DIR"
    if [[ ! -L "$OCSP_DIR/crl.pem" ]]; then
        ln -sf "$CRL_DIR/crl.pem" "$OCSP_DIR/crl.pem" || error_exit "Failed to link CRL file."
    else
        log "CRL file already linked at $OCSP_DIR/crl.pem"
        chown root:ocsp "$OCSP_DIR/crl.pem" || error_exit "Failed to set permissions for CRL file."
        chmod 644 "$OCSP_DIR/crl.pem" || error_exit "Failed to set permissions for CRL file."
        mkdir -p /etc/nginx/crl || error_exit "Failed to create CRL directory."
        chown root:root /etc/nginx/crl || error_exit "Failed to set permissions for CRL directory."
        chmod 755 /etc/nginx/crl || error_exit "Failed to set permissions for CRL directory."

        ln -sf "$CRL_DIR/crl.pem" "/etc/nginx/crl/crl.pem" || error_exit "Failed to link CRL file."
    fi

    # Configure NGINX to serve OCSP and CRL
    log "Configuring NGINX for OCSP and CRL..."
    cat > /etc/nginx/sites-available/ocsp <<EOF
server {
    listen 80;
    server_name _;

    access_log /var/log/nginx/ocsp_access.log;
    error_log /var/log/nginx/ocsp_error.log;

    location /ocsp {
        proxy_pass http://127.0.0.1:2560;
        proxy_set_header Host \$host;
        proxy_set_header X-Real-IP \$remote_addr;
        proxy_set_header X-Forwarded-For \$proxy_add_x_forwarded_for;
    }    

    types {
        application/pkix-crl crl.pem;
    }

    location /crl/crl.pem {
        alias /etc/nginx/crl/crl.pem;
        default_type application/pkix-crl;
        allow all;
    }

    location / {
        return 404;
    }

    add_header Content-Security-Policy "default-src 'self';";
    add_header X-Content-Type-Options nosniff;
    add_header X-Frame-Options DENY;
    add_header X-XSS-Protection "1; mode=block";
}

EOF
    
    chmod 644 /etc/nginx/sites-available/ocsp || error_exit "Failed to set permissions for NGINX site."
    chown root:root /etc/nginx/sites-available/ocsp || error_exit "Failed to set permissions for NGINX site."

    # Enable NGINX site
    if [[ ! -L /etc/nginx/sites-enabled/ocsp ]]; then
        ln -sf /etc/nginx/sites-available/ocsp /etc/nginx/sites-enabled/ocsp
    fi
    rm -f /etc/nginx/sites-enabled/default || error_exit "Failed to remove default NGINX site."

    # Restart NGINX
    log "Restarting NGINX..."
    systemctl restart nginx || error_exit "Failed to restart NGINX." 

    # Configure systemd for the OCSP responder
    log "Setting up systemd service for OCSP responder..."
    cat > /etc/systemd/system/ocsp-responder.service <<EOF
[Unit]
Description=OpenSSL OCSP Responder
After=network.target

[Service]
ExecStart=/usr/bin/openssl ocsp \
    -index $CRL_DB \
    -CA $CA_CERT \
    -rkey $OCSP_KEY \
    -rsigner $OCSP_CERT \
    -verify_other $OCSP_CERT \
    -VAfile $OCSP_CERT \
    -resp_no_certs \
    -timeout 60 \
    -nrequest 100 \
    -port $OCSP_PORT \
    -no_nonce

Restart=on-failure
User=ocsp
Group=ocsp
PrivateTmp=true
ProtectSystem=full
ProtectHome=true
NoNewPrivileges=true

[Install]
WantedBy=multi-user.target
EOF

    # Ensure OCSP user exists
    if ! id -u ocsp >/dev/null 2>&1; then
        log "Creating 'ocsp' user..."
        useradd -r -g ocsp -s /sbin/nologin ocsp || error_exit "Failed to create 'ocsp' user."
    fi

    chown ocsp:ocsp "$OCSP_DIR" "$OCSP_CERT" "$OCSP_KEY" "$CRL_DB" "$SRL_FILE"
            # Base directories and permissions
    setfacl -m u:ocsp:r /etc/swanctl/ocsp/ocsp-key.pem
    # Start and enable the OCSP responder service
    log "Reloading systemd daemon and starting OCSP responder service..."
    systemctl daemon-reload || error_exit "Failed to reload systemd daemon."
    systemctl enable ocsp-responder.service || error_exit "Failed to enable OCSP responder service."
    systemctl restart ocsp-responder.service || error_exit "Failed to restart OCSP responder service."

cat > /usr/local/bin/update_crl_and_restart_ocsp.sh <<EOF
#!/bin/bash

# Logging setup
LOGFILE="/var/log/update_crl_and_restart_ocsp.log"
echo "=== CRL Update Started: $(date) ===" >> "$LOGFILE"

# Update CRL
/path/to/ikpki.sh generate-crl full >> "$LOGFILE" 2>&1
if [[ $? -eq 0 ]]; then
    echo "CRL updated successfully." >> "$LOGFILE"
else
    echo "CRL update failed!" >> "$LOGFILE"
    exit 1
fi

# Restart OCSP Responder
systemctl restart ocsp-responder.service >> "$LOGFILE" 2>&1
if [[ $? -eq 0 ]]; then
    echo "OCSP responder restarted successfully." >> "$LOGFILE"
else
    echo "Failed to restart OCSP responder!" >> "$LOGFILE"
    exit 1
fi

echo "=== CRL Update Completed: $(date) ===" >> "$LOGFILE"

EOF

    chmod +x /usr/local/bin/update_crl_and_restart_ocsp.sh || error_exit "Failed to set permissions for update script."
    crontab -l | { cat; echo "0 2 */28 * * /usr/local/bin/update_crl_and_restart_ocsp.sh"; } | crontab - || error_exit "Failed to add cron job."

    log "OCSP responder and NGINX setup completed successfully!"
}


setup_firewalld() {

    log "Default gateway and interface updated in $CONFIG_PATH"
    log "Setting up Firewall rules for $DEFAULT_INTERFACE..."
 

    log "Disabling ICMP redirects for IPv4..."
    echo "net.ipv4.conf.all.send_redirects = 0" | tee -a /etc/sysctl.conf
    echo "net.ipv4.conf.default.rp_filter = 0" | tee -a /etc/sysctl.conf
    echo "net.ipv4.conf.all.accept_redirects = 0" | tee -a /etc/sysctl.conf
    log "Disabling ICMP redirects for IPv4 on $DEFAULT_INTERFACE..."
    echo "net.ipv4.conf.${DEFAULT_INTERFACE}.send_redirects = 0" | tee -a /etc/sysctl.conf
    echo "net.ipv4.conf.${DEFAULT_INTERFACE}.accept_redirects = 0" | tee -a /etc/sysctl.conf
    echo "net.ipv4.conf.${DEFAULT_INTERFACE}.rp_filter = 0" | tee -a /etc/sysctl.conf
    log "Disabling ICMP redirects for IPv6 on $DEFAULT_INTERFACE..."
    echo "net.ipv6.conf.${DEFAULT_INTERFACE}.accept_redirects = 0" | tee -a /etc/sysctl.conf
    log  "ICMP redirects permanently disabled on $DEFAULT_INTERFACE."
    if modprobe -q tcp_bbr 2>/dev/null \
    && printf '%s\n%s' "4.20" "$(uname -r)" | sort -C -V; then
    sysctl -w net.ipv4.tcp_congestion_control=bbr 2>/dev/null
    fi
    log "Disabling ICMP redirects for IPv6..."
    echo "net.ipv6.conf.all.accept_redirects = 0" | tee -a /etc/sysctl.conf
    echo "net.ipv6.conf.default.accept_redirects = 0" | tee -a /etc/sysctl.conf

    log  "ICMP redirects permanently disabled on all interfaces."

    log "Enabling IP forwarding..."
    echo "net.ipv4.ip_forward=1" | tee -a /etc/sysctl.conf
    sysctl -w net.ipv4.ip_forward=1
    sysctl --system
    sysctl -p



    chmod 640 /etc/nftables.conf || error_exit "failed to set permissions"
    systemctl enable nftables.service || error_exit "could not enable nftables service"
    systemctl start nftables.service || error_exit "could not start nftables"

    log "Firewall configuration for $VPN_MODE mode has been updated successfully."
        # Determine if IP pool rules are needed
    add_ip_pool_rules="no"
    if [ "$VPN_MODE" = "NAT" ] || [ "$VPN_MODE" = "ROUTED" ]; then
        add_ip_pool_rules="yes"
    fi


    cat <<EOF | tee /etc/nftables.conf >/dev/null
#!/usr/sbin/nft -f

flush ruleset

table inet firewall {

    set blacklisted_ips {
        type ipv4_addr;
        flags timeout;
    }

    set whitelisted_ips {
        type ipv4_addr;
        flags interval;
        elements = { $ROUTE_SUBNETS, 10.255.255.0/29, $PUBLIC_IP, 127.0.0.1 $( [ "$add_ip_pool_rules" = "yes" ] && echo ", $IP_POOL") }
    }

    chain mangle_PREROUTING {
        type filter hook prerouting priority mangle + 10;
        jump mangle_PRE_policy_allow-host-ipv6
        jump mangle_PREROUTING_ZONES
    }

    chain mangle_PRE_policy_allow-host-ipv6 {
        return
    }

    chain mangle_PREROUTING_ZONES {
        ip saddr @blacklisted_ips log prefix "BLACKLIST DROP: " limit rate 10/second counter drop
        
        $( [ "$add_ip_pool_rules" = "yes" ] && echo "ip saddr $IP_POOL counter goto mangle_PRE_client")
        ip saddr 127.0.0.1 counter goto mangle_PRE_trusted
        ip saddr 10.255.255.0/29 counter goto mangle_PRE_trusted
        iifname "lo:1" counter goto mangle_PRE_trusted
        iifname "lo" counter goto mangle_PRE_trusted
        iifname "$DEFAULT_INTERFACE" counter goto mangle_PRE_public
        counter goto mangle_PRE_public
    }

    chain mangle_PRE_client {
        return
    }

    chain mangle_PRE_trusted {
        return
    }

    chain mangle_PRE_public {
        return
    }

    chain nat_PREROUTING {
        type nat hook prerouting priority dstnat + 10;
        jump nat_PREROUTING_POLICIES_pre
        jump nat_PREROUTING_ZONES
        jump nat_PREROUTING_POLICIES_post
    }

    chain nat_PREROUTING_POLICIES_pre {
        jump nat_PRE_policy_allow-host-ipv6
    }

    chain nat_PRE_policy_allow-host-ipv6 {
        return
    }

    chain nat_PREROUTING_ZONES {
        $( [ "$add_ip_pool_rules" = "yes" ] && echo "ip saddr $IP_POOL counter goto nat_PRE_client")
        ip saddr 127.0.0.1 counter goto nat_PRE_trusted
        ip saddr 10.255.255.0/29 counter goto nat_PRE_trusted
        iifname "lo:1" counter goto nat_PRE_trusted
        iifname "lo" counter goto nat_PRE_trusted
        iifname "$DEFAULT_INTERFACE" counter goto nat_PRE_public
        counter goto nat_PRE_public
    }

    chain nat_PRE_client {
        return
    }

    chain nat_PRE_trusted {
        return
    }

    chain nat_PRE_public {
        return
    }

    chain nat_PREROUTING_POLICIES_post {
        return
    }

    chain nat_POSTROUTING {
        type nat hook postrouting priority srcnat + 10;
        jump nat_POSTROUTING_POLICIES_pre
        jump nat_POSTROUTING_ZONES
        jump nat_POSTROUTING_POLICIES_post
    }

    chain nat_POSTROUTING_POLICIES_pre {
        return
    }

    chain nat_POSTROUTING_ZONES {
        $( [ "$add_ip_pool_rules" = "yes" ] && echo "ip daddr $IP_POOL counter goto nat_POST_client")
        ip daddr 127.0.0.1 counter goto nat_POST_trusted
        ip daddr 10.255.255.0/29 counter goto nat_POST_trusted
        oifname "lo:1" counter goto nat_POST_trusted
        oifname "lo" counter goto nat_POST_trusted
        oifname "$DEFAULT_INTERFACE" counter goto nat_POST_public
        counter goto nat_POST_public
    }

    chain nat_POST_client {
        $( [ "$add_ip_pool_rules" = "yes" ] && echo "masquerade")
        return
    }

    chain nat_POST_trusted {
        return
    }

    chain nat_POST_public {
        return
    }

    chain nat_POSTROUTING_POLICIES_post {
        return
    }

    chain filter_PREROUTING {
        type filter hook prerouting priority filter + 10;
        icmpv6 type { nd-router-advert, nd-neighbor-solicit } accept
        meta nfproto ipv6 fib saddr . mark . iif oif missing drop
    }

    chain filter_INPUT {
        type filter hook input priority filter + 10; policy accept;
        ip saddr @blacklisted_ips log prefix "BLACKLIST DROP: " limit rate 10/second counter drop
        ct state invalid counter drop
        ct state { established, related } counter accept
        iifname "lo" counter accept
        jump filter_INPUT_ZONES
        ip saddr @whitelisted_ips counter accept
        ip saddr { 10.0.0.0/8, 172.16.0.0/12, 192.168.0.0/16 } counter drop
        ip6 saddr { fc00::/7 } counter drop
        counter reject with icmpx admin-prohibited
    }

    chain filter_FORWARD {
        type filter hook forward priority filter + 10; policy accept;
        ip saddr @blacklisted_ips log prefix "BLACKLIST DROP: " limit rate 10/second counter drop
        ct state invalid counter drop
        ct state { established, related } counter accept
        iifname "lo" counter accept
        jump filter_FORWARD_ZONES
        ip saddr @whitelisted_ips counter accept
        ip saddr { 10.0.0.0/8, 172.16.0.0/12, 192.168.0.0/16 } counter drop
        ip6 saddr { fc00::/7 } counter drop
        counter reject with icmpx admin-prohibited
    }

    chain filter_FORWARD_ZONES {
        $( [ "$VPN_MODE" = "NAT" ] || [ "$VPN_MODE" = "ROUTED" ] && echo "ip saddr $IP_POOL counter goto filter_FWD_client")
        return
    }

    chain filter_FWD_client {
        $( [ "$VPN_MODE" = "NAT" ] || [ "$VPN_MODE" = "ROUTED" ] && echo "ip daddr $IP_POOL counter accept")
        $( [ "$VPN_MODE" = "NAT" ] || [ "$VPN_MODE" = "ROUTED" ] && echo "ip saddr $IP_POOL counter accept")
    }

    chain filter_OUTPUT {
        type filter hook output priority filter + 10; policy accept;
        ip daddr @blacklisted_ips log prefix "OUTGOING BLACKLIST DROP: " limit rate 10/second counter drop
        ct state { established, related } counter accept
        oifname "lo" counter accept
        ip6 daddr { ::/96, ::ffff:0.0.0.0/96, 2002::/24, 2002:a00::/24, 2002:7f00::/24, 2002::/16 } counter drop
    }

    chain filter_INPUT_ZONES {
        $( [ "$add_ip_pool_rules" = "yes" ] && echo "ip saddr $IP_POOL counter goto filter_IN_client")
        ip saddr 127.0.0.1 counter goto filter_IN_trusted
        ip saddr 10.255.255.0/29 counter goto filter_IN_trusted
        iifname "lo:1" counter goto filter_IN_trusted
        iifname "lo" counter goto filter_IN_trusted
        iifname "$DEFAULT_INTERFACE" counter goto filter_IN_public
        counter goto filter_IN_public
    }

    chain filter_IN_public {
        meta l4proto { icmp, ipv6-icmp } counter accept
        tcp dport 22 counter accept
        udp dport { 500, 4500, 53 } counter accept
        tcp dport { 80, 53, 9090 } counter accept
        meta l4proto esp counter accept
        ip saddr @whitelisted_ips counter accept
        ip saddr { 10.0.0.0/8, 172.16.0.0/12, 192.168.0.0/16 } counter drop
        ip6 saddr { fc00::/7 } counter drop
        counter reject with icmpx admin-prohibited
    }

    chain filter_IN_trusted {
        counter accept
    }

    chain filter_IN_client {
        counter accept
    }

}

table ip mangle {
    chain mangle_FORWARD {
        type filter hook forward priority mangle + 10; policy accept;
        oifname "$DEFAULT_INTERFACE" tcp flags syn / syn,rst tcp option maxseg size set rt mtu
    }

    chain mangle_POSTROUTING {
        type filter hook postrouting priority mangle + 10; policy accept;
        oifname "$DEFAULT_INTERFACE" tcp flags syn / syn,rst tcp option maxseg size set rt mtu
    }
}

table ip filter {
    chain FORWARD {
        type filter hook forward priority filter; policy accept; counter
        $( [ "$add_ip_pool_rules" = "yes" ] && echo "oifname \"$DEFAULT_INTERFACE\" ip saddr $IP_POOL counter accept")
        $( [ "$add_ip_pool_rules" = "yes" ] && echo "iifname \"$DEFAULT_INTERFACE\" ip daddr $IP_POOL counter accept")
    }
}
EOF

        chmod 640 /etc/nftables.conf  || error_exit "failed to set permissions"
        nft -c -f /etc/nftables.conf || error_exit "failed nftables syntax config check"
        systemctl enable nftables.service || error_exit "could not enable nf tables service"
        systemctl start nftables.service || error_exit "could not start nf tables"
        nft -f /etc/nftables.conf || error_exit "failed to load nftables configuration"
        echo "firewall configuration has been updated successfully."   
      
      
 
    log "Disabling Hardware offloading on $DEFAULT_INTERFACE..."
    ethtool -K "$DEFAULT_INTERFACE" rx off tx off sg off tso off gso off gro off lro off || error_exit "Failed to disable offloading on $DEFAULT_INTERFACE"

    echo "Default interface detected: $DEFAULT_INTERFACE"


    INTERFACES_FILE="/etc/network/interfaces"


    if ! grep -q "iface $DEFAULT_INTERFACE inet" "$INTERFACES_FILE"; then
        echo "Interface $DEFAULT_INTERFACE not found in $INTERFACES_FILE. Adding configuration."


        echo -e "\nauto $DEFAULT_INTERFACE\niface $DEFAULT_INTERFACE inet dhcp\n    post-up /sbin/ethtool -K $DEFAULT_INTERFACE rx off tx off sg off tso off gso off gro off lro off" | tee -a "$INTERFACES_FILE" > /dev/null
        echo "Offloading settings added to $INTERFACES_FILE for $DEFAULT_INTERFACE."
    else
        echo "Interface $DEFAULT_INTERFACE found in $INTERFACES_FILE. Checking for offloading settings."
        if ! grep -q "post-up /sbin/ethtool -K $DEFAULT_INTERFACE rx off tx off sg off tso off gso off gro off lro off" "$INTERFACES_FILE"; then
            sed -i "/iface $DEFAULT_INTERFACE inet/a \ \ \ \ post-up /sbin/ethtool -K $DEFAULT_INTERFACE rx off tx off sg off tso off gso off gro off lro off" "$INTERFACES_FILE"
            echo "Offloading settings added to existing configuration in $INTERFACES_FILE for $DEFAULT_INTERFACE."
        else
            echo "Offloading settings already exist in $INTERFACES_FILE for $DEFAULT_INTERFACE."
        fi
    fi

}

save_nft_config() {
    echo "Saving nftables configuration for persistence..."

    nft list ruleset > /etc/nftables.conf

    systemctl restart nftables

    echo "Nftables configuration saved and service restarted."
}


debug_strongswan() {
    run_command() {
        local cmd="$1"
        local description="$2"

        log "Running: $description"
        echo "-----------------------------------------------------------------------------------------------------"
        if ! eval "$cmd"; then
            log "ERROR: Failed to execute: $description"
        fi
        echo "-----------------------------------------------------------------------------------------------------"
    }

    check_service() {
        local service_name="$1"
        if ! systemctl is-active --quiet "$service_name"; then
            log "ERROR: $service_name is not running. Starting it now..."
            systemctl start "$service_name"
            sleep 5
        else
            log "$service_name is running."
        fi
        run_command "systemctl status $service_name --no-pager -l" "$service_name status"
    }

    log "Starting Gateway service status & log debug..."
    check_service "strongswan.service"
    check_service "ragent"
    check_service "frr"
    check_service "nginx"
    check_service "fail2ban"
    check_service "ocsp-responder"
    check_service "suricata"
    check_service "cron"
    crontab -l
    check_service "suricata_watchdog.service"
    run_command "swanctl --list-conns" "Loaded connections"
    run_command "swanctl --list-certs" "Loaded certificates"
    run_command "swanctl --list-sas" "Active IKE SAs"
    run_command "ip xfrm policy show" "XFRM policies"
    run_command "ip xfrm state show" "XFRM states"
    run_command "ss -tuln" "Open TCP/UDP ports and listening services"
    run_command "ip route show" "IP routing table"
    run_command "fail2ban-client status"

    if command -v nft &> /dev/null; then
        #run_command "nft list ruleset" "Full nftables ruleset"
        run_command "nft list chains inet" "listing chains"
        run_command "nft list chain inet firewall filter_INPUT" "Firewall input"
        run_command "nft list chain inet firewall filter_IN_public" "Public zone"
        run_command "nft list chain inet firewall filter_IN_client" "Client zone"
        run_command "nft list chain inet firewall filter_INPUT_ZONES" "Input zones"
        run_command "nft list chain inet firewall filter_FORWARD" "Firewall forward"
        run_command "nft list chain inet firewall filter_OUTPUT" "Firewall output"
        run_command "nft list chain inet firewall mangle_PREROUTING_ZONES" "Firewall prerouting"
        run_command "nft list set inet firewall blacklisted_ips" "Blacklisted IPs" 
        run_command "nft list set inet firewall whitelisted_ips" "Whitelisted IPs"
        else
        log "NFTables is not installed. Skipping nftables checks."
    fi

    if command -v vtysh &> /dev/null; then
        run_command "vtysh -c 'show ip ospf neighbor'" "OSPF neighbors"
        run_command "vtysh -c 'show ip ospf route'" "OSPF routes"
        run_command "vtysh -c 'show ip ospf'" "OSPF general information"
    else
        log "vtysh is not installed. Skipping OSPF checks."
    fi

    run_command "journalctl -u strongswan.service --no-pager -n 50" "Last 50 lines of StrongSwan logs"
    echo "-----------------------------------------------------------------------------------------------------"
    log "suricata logs last 20 lines"
    echo "-----------------------------------------------------------------------------------------------------"
    tail -n 20 /var/log/suricata/stats.log
    tail -n 20 /var/log/suricata/fast.log
    tail -n 20 /var/log/suricata/eve.json
    echo "-----------------------------------------------------------------------------------------------------"
    log "last 20 Okta group verify logs"
    echo "-----------------------------------------------------------------------------------------------------"
    tail -n 20 /var/log/swanctl_user_check.log
    echo "-----------------------------------------------------------------------------------------------------"
    log "last 20 Suricata watchdog logs"
    echo "-----------------------------------------------------------------------------------------------------"
    tail -n 20 /var/log/suricata_watchdog_actions/actions.log
    echo "-----------------------------------------------------------------------------------------------------"
    log "IPsec Gateway debug output."
}


load_and_export_config() {
    local CONFIG_PATH="/etc/strongconn.conf"
    
    if [ ! -f "$CONFIG_PATH" ]; then
        echo "Configuration file not found!"
        return 1
    fi

    source "$CONFIG_PATH"
    export EMAIL_ADDRESS
    export DNS_NAME
    export ROUTE_SUBNETS
    export DNS_SERVERS
    export RADIUS_SECRET
    export PUBLIC_IP
    export IP_POOL
    export IP_RANGE
    export PFX_PASSWORD
}

inject_Banner(){

cat << EOF > /etc/motd
======================================================================================================
ikev2 ipsec concentrator v1.0 
======================================================================================================
  Welcome to Strongswan IKEv2 Gateway
======================================================================================================
 PKI management:
    ikpki.sh
 Load changes:
    swanctl --load-all
 Debugging output:
    strongconn.sh -debug
site-to-site:
    tunnel.sh
======================================================================================================
Update strongswan package from source:
------------------------------------------------------------------------------------------------------
    systemctl stop strongswan    
    cd  /usr/src/strongswan-CURRENT_VERSION/ 
             make uninstall   
    cd ~/ 
    strongconn.sh -update
======================================================================================================
Check other kernel modules & load on boot:
     srongconn.sh -check-comp 
======================================================================================================
VPN-MODE $VPN_MODE
------------------------------------------------------------------------------------------------------
NOTE:Blacklist is dynamic to disable stop systemctl stop suricata-watchdog.serivce 
     add additional addresses to ipset whitelist to disable blocking the address.
     ipset add whitelisted_ips x.x.x.x
======================================================================================================
User tar Bundles@ /opt/pki
======================================================================================================
EOF

echo "/etc/motd updated"
}

start_vpn() {
    log "Starting IPsec services..."
    systemctl enable strongswan.service
    systemctl start strongswan.service
    sleep 5
    if systemctl is-active --quiet strongswan.service; then
        swanctl --load-all
        log "VPN services started."
    else
        log "Failed to start VPN services. check systemctl status or debug for more details."
        exit 1
    fi
}

backup_config() {

    CONFIG_ITEMS=("/etc/swanctl" "/etc/strongswan.d" "/etc/strongswan.conf")
    BACKUP_DIR="/var/backups/strongswan-config-LATEST_BACKUP"

    log "Removing existing backup directory: $BACKUP_DIR"
    rm -rf "$BACKUP_DIR" 2>/dev/null

    log "Creating backup directory: $BACKUP_DIR"
    mkdir -p "$BACKUP_DIR"

    for ITEM in "${CONFIG_ITEMS[@]}"; do
        if [ -e "$ITEM" ]; then
            log "Backing up $ITEM to $BACKUP_DIR"
            cp -a "$ITEM" "$BACKUP_DIR"
        else
            log "Warning: $ITEM does not exist and will not be backed up."
        fi
    done

    local date=$(date +%Y%m%d_%H%M%S)
    tar -czpf "/var/backups/strongswan-backup-$date.tar.gz" -C "$(dirname "$BACKUP_DIR")" "$(basename "$BACKUP_DIR")"
    log "Backup complete: /var/backups/strongswan-backup-$date.tar.gz"
}

restore_config() {

    CONFIG_ITEMS=("/etc/swanctl" "/etc/strongswan.d" "/etc/strongswan.conf")
    BACKUP_DIR="/var/backups/strongswan-config-LATEST_BACKUP"
    
    if [ ! -d "$BACKUP_DIR" ]; then
        echo "Backup directory $BACKUP_DIR does not exist. Cannot restore."
        return 1
    fi

    for ITEM in "${CONFIG_ITEMS[@]}"; do
        BASENAME=$(basename "$ITEM")
        if [ -e "$BACKUP_DIR/$BASENAME" ]; then
            log "Restoring $ITEM from $BACKUP_DIR..."
            rsync -a "$BACKUP_DIR/$BASENAME" "$(dirname "$ITEM")/"
            log "Restored $ITEM successfully."
        else
            log "Warning: $ITEM does not exist in the backup. Skipping..."
    
        fi
        done
    log "Reloading systemd configuration..."
    cat <<EOF | tee /lib/systemd/system/strongswan.service
[Unit]
Description=strongSwan IPsec IKEv1/IKEv2 daemon using swanctl
After=network.target

[Service]
Type=notify
ExecStartPre=/bin/mkdir -p /var/run/charon
ExecStartPre=/bin/chown root:strongswan /var/run/charon
ExecStartPre=/bin/chmod 770 /var/run/charon
ExecStartPre=/bin/touch /var/run/charon.vici
ExecStartPre=/bin/chown root:strongswan /var/run/charon.vici
ExecStartPre=/bin/chmod 770 /var/run/charon.vici
ExecStart=/usr/sbin/charon-systemd
Restart=on-failure
KillMode=process

[Install]
WantedBy=multi-user.target
EOF
    log "Reloading systemd configuration and starting StrongSwan service..."
    systemctl daemon-reload
    systemctl enable strongswan
    systemctl start strongswan
    tree -a -p -h -D /etc/swanctl
    tree -a -p -h -D /etc/strongswan.d
    log "config restore complete."
  
}

# shellcheck source=/dev/null
export_cert_to_p12_tar() {
    local OUTPUT_DIR="/root"
    local P12_FILE="${OUTPUT_DIR}/${DNS_NAME}.p12"
    local TAR_FILE="${OUTPUT_DIR}/${DNS_NAME}_certs.tar.gz"
    local CERT_PATH="/etc/letsencrypt/live/${DNS_NAME}/fullchain.pem"
    local KEY_PATH="/etc/letsencrypt/live/${DNS_NAME}/privkey.pem"
    local CONFIG_PATH="/etc/strongconn.conf"
   
    if [ ! -f "$CERT_PATH" ] || [ ! -f "$KEY_PATH" ]; then
        echo "Certificate or key file not found for domain ${DNS_NAME}."
        return 1
    fi
    openssl pkcs12 -export -out "$P12_FILE" -inkey "$KEY_PATH" -in "$CERT_PATH" -name "Okta Cert" -passout pass:"$PFX_PASSWORD"
    if [ $? -ne 0 ]; then
        echo "Failed to export certificate to PKCS#12 format."
        return 1
    fi
    tar -czf "$TAR_FILE" -C "$OUTPUT_DIR" "$(basename "$P12_FILE")"
    if [ $? -ne 0 ]; then
        echo "Failed to create tar.gz archive."
        return 1
    fi
    rm -f "$P12_FILE"
    echo "Certificate exported and packaged successfully to ${TAR_FILE}."
    return 0
}

write_okta_profile() {

    load_and_export_config

    local oktapowershell_script="/opt/pki/okta_vpn_profile_setup.ps1"

    
    cat <<EOF > "$oktapowershell_script"
# Variables
\$vpnName = "$DNS_NAME"
\$serverAddress = "$DNS_NAME"
\$dnsSuffix = "$S_DOMAIN"
\$destinationPrefix = "$ROUTE_SUBNETS"

Remove-ItemProperty -Path "HKLM:\System\CurrentControlSet\Services\Rasman\Parameters" -Name "NegotiateDH2048_AES256" -ErrorAction SilentlyContinue


function Remove-VpnConnectionIfExists {
    try {
        \$existingVpn = Get-VpnConnection -Name \$vpnName -ErrorAction SilentlyContinue
        if (\$existingVpn) {
            Write-Host "Removing existing VPN profile '\$vpnName'."
            Remove-VpnConnection -Name \$vpnName -Force
        }
    } catch {
        Write-Host "No existing VPN connection found with the name '\$vpnName'. Proceeding to add new connection."
    }
}

Add-RegistryKey
Remove-VpnConnectionIfExists

# Create the EAP configuration XML content
\$eapXmlContent = @"
<EapHostConfig xmlns="http://www.microsoft.com/provisioning/EapHostConfig">
  <EapMethod>
    <Type xmlns="http://www.microsoft.com/provisioning/EapCommon">21</Type>
    <VendorId xmlns="http://www.microsoft.com/provisioning/EapCommon">0</VendorId>
    <VendorType xmlns="http://www.microsoft.com/provisioning/EapCommon">0</VendorType>
    <AuthorId xmlns="http://www.microsoft.com/provisioning/EapCommon">311</AuthorId>
  </EapMethod>
  <Config xmlns="http://www.microsoft.com/provisioning/EapHostConfig">
    <EapTtls xmlns="http://www.microsoft.com/provisioning/EapTtlsConnectionPropertiesV1">
      <ServerValidation>
        <ServerNames></ServerNames>
        <DisableUserPromptForServerValidation>false</DisableUserPromptForServerValidation>
      </ServerValidation>
      <Phase2Authentication>
        <PAPAuthentication />
      </Phase2Authentication>
      <Phase1Identity>
        <IdentityPrivacy>false</IdentityPrivacy>
        <AnonymousIdentity>false</AnonymousIdentity>
      </Phase1Identity>
    </EapTtls>
  </Config>
</EapHostConfig>
"@

# Convert the XML string to an XML object
\$eapXml = [xml]\$eapXmlContent

# Create the VPN connection with the specified EAP configuration
try {
    # Remove existing VPN connection if it exists
    Remove-VpnConnectionIfExists

    # Add the VPN connection with the chosen DH group
    Add-VpnConnection -Name \$vpnName \`
        -ServerAddress \$serverAddress \`
        -TunnelType IKEv2 \`
        -EncryptionLevel Maximum \`
        -AuthenticationMethod Eap \`
        -EapConfigXmlStream \$eapXml.OuterXml \`
        -RememberCredential \$False \`
        -SplitTunneling \`
        -DnsSuffix \$dnsSuffix \`
        -Force

 
   Set-VpnConnectionIPsecConfiguration -ConnectionName "\$vpnname" \`
        -AuthenticationTransformConstants GCMAES256 \`
        -CipherTransformConstants GCMAES256 \`
        -EncryptionMethod AES256 \`
        -IntegrityCheckMethod SHA256 \`
        -DHGroup ECP256 \`
        -PfsGroup ECP256 \`
        -PassThru -Force 
    
    Write-Host "VPN profile '\$vpnName' created successfully. It will prompt for username and password."

    # Add the route to the VPN connection
    Add-VpnConnectionRoute -ConnectionName \$vpnName \`
        -DestinationPrefix \$destinationPrefix \`
        -PassThru

    Write-Host "Route added to VPN profile '\$vpnName'."

    # Display the VPN profile details
    \$vpnProfile = Get-VpnConnection -Name \$vpnName
    Write-Host "VPN Profile Details:"
    \$vpnProfile | Format-List
} catch {
    Write-Host "Failed to configure the VPN profile: \$_"
    Exit 1
}

EOF
     log "Okta IPsec EAP-TTLS-PAP profile written to $oktapowershell_script"
}


switch_vpn_config() {
    local CONFIG_FILE="/etc/swanctl/swanctl.conf"
    local CONFIG_PATH="/etc/strongconn.conf"
    local CRON_JOB="*/15 * * * * env -i /usr/bin/python3 /var/lib/strongswan/okta-group-verify.py >> /var/log/okta-group-verify.log 2>&1"
    load_and_export_config
    if [ "$VPN_MODE" = "NAT" ] || [ "$VPN_MODE" = "ROUTED" ]; then
        client_pool="main-pool"
    else
        client_pool="dhcp"
    fi

    local OKTA_CONFIG="
connections {
    eap-ttls-pap {
        version = 2
        proposals = aes256-sha256-ecp256, aes256-sha256-modp2048, aes256gcm16-prfsha256-ecp256, aes128-sha256-modp2048, aes256-sha1-modp2048, aes256-sha384-modp2048, aes256-sha256-ecp384, aes256-sha384-ecp384, aes256-sha256-ecp521, aes256gcm16-sha256-ecp256
        encap = yes
        dpd_delay = 30s
        dpd_timeout = 120s
        local {
            auth = pubkey
            certs = /etc/swanctl/x509/${DNS_NAME}.${DNS}.server.pem
            id = ${DNS_NAME}
        }
        remote {
            auth = eap-radius
            id = %any
            eap_id = 1
        }
        children {
            net {
                local_ts = 0.0.0.0/0
                remote_ts = dynamic
                rekey_time = 0s
                start_action = none
                dpd_action = restart
                mode = tunnel
                esp_proposals = aes256-sha256, aes128gcm16-modp2048, aes256gcm16-modp2048, aes128-sha256-modp2048, aes256-sha256-modp2048, aes256gcm16-ecp256, aes256gcm16 
            }
        }
        pools = ${client_pool}
        mobike = yes
        fragmentation = yes
    }
}


pools {
    main-pool {
        addrs = ${IP_POOL}
        dns = ${DNS_SERVERS}
    }
}

secrets {
    eap-radius {
        id = ${DNS_NAME}
        secret = ${RADIUS_SECRET}
    }
    private-key {
        id = ${DNS_NAME}
        file = /etc/swanctl/private/${DNS_NAME}.server.key.pem
    }
}

authorities {
    vpn-ca {
        cacert = /etc/swanctl/x509ca/ca.pem
        ocsp_uris = [ "http://$PUBLIC_IP:2560" ]
    }
}

"

    local PUBKEY_CONFIG="
connections {
    ikev2-cp {
        version = 2
        proposals = aes256-sha256-ecp256, aes256-sha256-modp2048, aes256gcm16-prfsha256-ecp256, aes128-sha256-modp2048, aes256-sha1-modp2048, aes256-sha384-modp2048, aes256-sha256-ecp384, aes256-sha384-ecp384, aes256-sha256-ecp521, aes256gcm16-sha256-ecp256
        encap = yes
        dpd_delay = 30s
        dpd_timeout = 300s
        local {
            auth = pubkey
            certs = /etc/swanctl/x509/server.pem
            id = ${PUBLIC_IP}
        }
        remote {
            auth = pubkey
            revocation = ifuri
            id = %any
        }
        children {
            net {
                local_ts = 0.0.0.0/0
                remote_ts = dynamic
                rekey_time = 0s
                start_action = none
                dpd_action = restart
                mode = tunnel
                esp_proposals = aes256-sha256, aes128gcm16-modp2048, aes256gcm16-modp2048, aes128-sha256-modp2048, aes256-sha256-modp2048, aes256gcm16-ecp256, aes256gcm16   
        }
        pools = ${client_pool}
        mobike = yes
        fragmentation = yes
    }
}

pools {
    main-pool {
        addrs = ${IP_POOL}
        dns = ${DNS_SERVERS}
    }
}

secrets {
    private-key {
        id = ${PUBLIC_IP}
        file = /etc/swanctl/private/server-key.pem
    }
}

authorities {
    vpn-ca {
        cacert = /etc/swanctl/x509ca/ca.pem
        ocsp_uris = [ "http://$PUBLIC_IP:2560" ]
    }
}

"

    local BOTH_CONFIG="
connections {
    eap-ttls-pap {
        version = 2
        proposals = aes256-sha256-ecp256, aes256-sha256-modp2048, aes256gcm16-prfsha256-ecp256, aes128-sha256-modp2048, aes256-sha1-modp2048, aes256-sha384-modp2048, aes256-sha256-ecp384, aes256-sha384-ecp384, aes256-sha256-ecp521, aes256gcm16-sha256-ecp256
        encap = yes
        dpd_delay = 30s
        dpd_timeout = 120s
        local {
            auth = pubkey
            certs = /etc/swanctl/x509/${DNS_NAME}.${DNS}server.pem
            id = ${DNS_NAME}
        }
        remote {
            auth = eap-radius
            id = %any
            eap_id = 1
        }
        children {
            net {
                local_ts = 0.0.0.0/0
                remote_ts = dynamic
                rekey_time = 0s
                start_action = none
                dpd_action = restart
                mode = tunnel
               esp_proposals = aes256-sha256, aes128gcm16-modp2048, aes256gcm16-modp2048, aes128-sha256-modp2048, aes256-sha256-modp2048, aes256gcm16-ecp256, aes256gcm16
            }
        }
        pools = ${client_pool}
        mobike = yes
        fragmentation = yes
    }
    ikev2-cp {
        version = 2
        proposals = aes256-sha256-ecp256, aes256-sha256-modp2048, aes256gcm16-prfsha256-ecp256, aes128-sha256-modp2048, aes256-sha1-modp2048, aes256-sha384-modp2048, aes256-sha256-ecp384, aes256-sha384-ecp384, aes256-sha256-ecp521, aes256gcm16-sha256-ecp256
        encap = yes
        dpd_delay = 30s
        dpd_timeout = 300s
        local {
            auth = pubkey
            revocation = ifuri
            certs = /etc/swanctl/x509/server.pem
            id = ${PUBLIC_IP}
        }
        remote {
            auth = pubkey
            revocation = ifuri
            id = %any
        }
        children {
            net {
                local_ts = 0.0.0.0/0
                remote_ts = dynamic
                rekey_time = 0s
                start_action = none
                dpd_action = restart
                mode = tunnel
                esp_proposals = aes256-sha256, aes128gcm16-modp2048, aes256gcm16-modp2048, aes128-sha256-modp2048, aes256-sha256-modp2048, aes256gcm16-ecp256, aes256gcm16
            }
        }
        pools = ${client_pool}
        mobike = yes
        fragmentation = yes
    }
}

pools {
    main-pool {
        addrs = ${IP_POOL}
        dns = ${DNS_SERVERS}
    }
}

secrets {
    eap-radius {
        id = ${DNS_NAME}
        secret = ${RADIUS_SECRET}
    }
    private-key {
        id = ${PUBLIC_IP}
        file = /etc/swanctl/private/server-key.pem
    }
    private-key {
        id = ${DNS_NAME}
        file = /etc/swanctl/private/${DNS_NAME}.server.key.pem
    }
}

authorities {
    vpn-ca {
        cacert = /etc/swanctl/x509ca/ca.pem
        ocsp_uris = [ "http://$PUBLIC_IP/2560" ]
    }
}


"
    if [ "$1" == "okta" ]; then
        echo "Switching to Okta configuration..."
        backup_config
        echo "Configuration backed up successfully to /var/backups..."
        echo "$OKTA_CONFIG" > "$CONFIG_FILE"
        
        # Check if the cron job already exists
        if crontab -l | grep -q "/var/lib/strongswan/okta-group-verify.py"; then
            echo "Cron job already exists."
        else
            # Add the cron job if it doesn't exist
            (crontab -l 2>/dev/null; echo "$CRON_JOB") | crontab -
            echo "Cron job added successfully."
        fi

    elif [ "$1" == "pubkey" ]; then
        echo "Switching to Public Key configuration..."
        echo "$PUBKEY_CONFIG" > "$CONFIG_FILE"
        
        # Remove the cron job if it exists
        crontab -l | grep -v "/var/lib/strongswan/okta-group-verify.py" | crontab -
        echo "Cron job removed successfully."

    elif [ "$1" == "both" ]; then
        echo "Switching to Both Okta and Public Key configuration..."
        echo "$BOTH_CONFIG" > "$CONFIG_FILE"
        
        # Check if the cron job already exists
        if crontab -l | grep -q "/var/lib/strongswan/okta-group-verify.py"; then
            echo "Cron job already exists."
        else
            # Add the cron job if it doesn't exist
            (crontab -l 2>/dev/null; echo "$CRON_JOB") | crontab -
            echo "Cron job added successfully."
        fi

    else
        echo "Usage: switch_vpn_config {okta|pubkey|both}"
        exit 1
    fi

    # Reload StrongSwan configuration
    swanctl --load-all
    swanctl --list-conns
    swanctl --list-certs
    swanctl --list-authorities
}

install_suricata(){
        load_config
        log "returning back to the script directory"
        cd "$SCRIPT_DIR" || exit
   
        log " Copy and set permissions for Python scripts"
        cp ./okta-group-verify.py /var/lib/strongswan/ || error_exit "Failed to copy okta-group-verify.py to /var/lib/strongswan/."
        chmod 700 /var/lib/strongswan/okta-group-verify.py || error_exit "Failed to set permissions on /var/lib/strongswan/okta-group-verify.py."
        chown root:root /var/lib/strongswan/okta-group-verify.py || error_exit "Failed to change ownership of /var/lib/strongswan/okta-group-verify.py."
        cp ./suricata_watchdog.py /var/lib/strongswan/ || error_exit "Failed to copy suricata_watchdog.py to /var/lib/strongswan/."
        chmod 700 /var/lib/strongswan/suricata_watchdog.py || error_exit "Failed to set permissions on /var/lib/strongswan/suricata_watchdog.py."
        chown root:root /var/lib/strongswan/suricata_watchdog.py || error_exit "Failed to change ownership of /var/lib/strongswan/suricata_watchdog.py."
    

        log "Installing Suricata..."
        systemctl daemon-reload
        log "installing suricata"
        apt-get install suricata -y

        suricata-update
         cat <<EOF | tee /etc/default/suricata > /dev/null || error_exit "Failed to create /etc/default/suricata."
# Default configuration for Suricata

# Set to "true" to start the service
RUN="true"

# Configuration file to load
SURCONF=/etc/suricata/suricata.yaml

# Listen mode: netmap for inline processing
LISTENMODE=af-packet

# Interface to listen on (netmap mode)
IFACE="$DEFAULT_INTERFACE"

# Queue number to listen on (not used in netmap mode)
NFQUEUE=0

# Load Google TCMALLOC if libtcmalloc-minimal4 is installed
TCMALLOC="true"

# Pid file
PIDFILE=/var/run/suricata.pid
EOF
log "Backup existing suricata.yaml if it exists"
if [[ -f "/etc/suricata/suricata.yaml" ]]; then
      log "Backing up existing suricata.yaml..."
      cp /etc/suricata/suricata.yaml /etc/suricata/suricata.yaml.bak || error_exit "Failed to backup existing suricata.yaml."
fi

log "Create Suricata YAML configuration"
        log "Creating Suricata YAML configuration..."
     cat <<EOF | tee /etc/suricata/suricata.yaml > /dev/null
%YAML 1.1
---
vars:
  address-groups:
    HOME_NET: "[$ROUTE_SUBNETS,$IP_POOL,$DEFAULT_GATEWAY]"
    EXTERNAL_NET: "!\$HOME_NET"
    HTTP_SERVERS: "[$ROUTE_SUBNETS,$DEFAULT_GATEWAY]"
    SQL_SERVERS: "[$ROUTE_SUBNETS]"
    MYSQL_SERVERS: "[$ROUTE_SUBNETS]"
    POSTGRESQL_SERVERS: "[$ROUTE_SUBNETS]"
    MSSQL_SERVERS: "[$ROUTE_SUBNETS]"
    TELNET_SERVERS: "[$ROUTE_SUBNETS]"
    SMTP_SERVERS: "[$ROUTE_SUBNETS]"
    DNS_SERVERS: "[$DNS_SERVERS,$DEFAULT_GATEWAY]"
    DEVELOPMENT_TOOLS: "[$ROUTE_SUBNETS]"
    GIT_REPOSITORIES: "[$ROUTE_SUBNETS]"
    BUILD_SERVERS: "[$ROUTE_SUBNETS]"
    QA_SERVERS: "[$ROUTE_SUBNETS]"
    VNC_SERVERS: "[$ROUTE_SUBNETS]"
    RDP_SERVERS: "[$ROUTE_SUBNETS]"

  port-groups:
    SHELLCODE_PORTS: "[80,443,8080,9090]"
    SSH_PORTS: "[22]"
    TELNET_PORTS: "[23]"
    HTTP_PORTS: "[80,443,8080,9090]"
    MYSQL_PORTS: "[3306]"
    POSTGRESQL_PORTS: "[5432]"
    MSSQL_PORTS: "[1433,1434]"
    REDIS_PORTS: "[6379,6380]"
    MONGODB_PORTS: "[27017]"
    FTP_PORTS: "[20,21]"
    SMTPS_PORTS: "[465]"
    IMAPS_PORTS: "[993]"
    POP3S_PORTS: "[995]"
    ORACLE_PORTS: "[1521,2483,2484]"
    RADIUS_PORTS: "[1812,1813]"
    VNC_PORTS: "[5900,5901]"
    RDP_PORTS: "[3389]"

default-rule-path: /var/lib/suricata/rules
rule-files:
  - suricata.rules

community-id: true

app-layer:
  protocols:
    http:
      enabled: true
    http2:
      enabled: true
    tls:
      enabled: true
    dns:
      enabled: true
    ftp:
      enabled: true
    smb:
      enabled: true
    rdp:
      enabled: true
    vnc:
      enabled: true
    rfb:
      enabled: true
    smtp:
      enabled: true
    ssh:
      enabled: true
    dhcp:
      enabled: true
    dcerpc:
      enabled: true
    enip:
      enabled: true
    nfs:
      enabled: true
    ntp:
      enabled: true
    tftp:
      enabled: true
    krb5:
      enabled: true
    snmp:
      enabled: true
    sip:
      enabled: true
    mqtt:
      enabled: true
    modbus:
      enabled: false
    dnp3:
      enabled: false
    imap:
      enabled: true

stats:
  enabled: true
  interval: 10

stream:
  memcap: 4gb
  memcap-policy: drop-flow
  inline: false

suppress:
  - gid: 1
    sid: 2260002
    track: by_src
    ip: 127.0.0.1
  - gid: 1
    sid: 1234567
    track: by_dst
    ip: 127.0.0.1
  - gid: 1
    sid: 2260003
    track: by_src
    ip: 10.255.255.1
  - gid: 1
    sid: 1234568
    track: by_dst
    ip: 10.255.255.1

af-packet:
  - interface: $DEFAULT_INTERFACE
    threads: auto
    cluster-type: cluster_flow
    cluster-id: 99
    defrag: true
    use-mmap: true
    tpacket-v3: true
    ring-size: 4096
    block-size: 1048576
    use-emergency-flushing: true
    emergency-recovery: 70
    default-mode: ids
    buffer-size: 1500

detect-engine:
  profile: medium
  rule-reload: true
  thread-ratio: 1.0

unix-command:
  enabled: true

default-mode: ids

outputs:
  - fast:
      enabled: true
      filename: /var/log/suricata/fast.log
  - eve-log:
      enabled: true
      filetype: regular
      filename: /var/log/suricata/eve.json
      types:
        - alert:
            tagged-packets: true
  - stats:
      enabled: true
      filename: /var/log/suricata/stats.log
      interval: 90

logging:
  default-log-level: info
  outputs:
    - console:
        enabled: true
        level: info
    - file:
        enabled: true
        level: info
        filename: /var/log/suricata/suricata.log
    - syslog:
        enabled: true
        facility: local1
        level: info
EOF


        log "Validating Suricata YAML configuration..."
        
        log "Downloading and installing Suricata rules..."
        wget https://rules.emergingthreats.net/open/suricata-8.0.0/emerging.rules.tar.gz -O /tmp/emerging.rules.tar.gz || error_exit "Failed to download Suricata rules."
        tar -xzf /tmp/emerging.rules.tar.gz -C /var/lib/suricata/ || error_exit "Failed to extract Suricata rules."

        chmod -R 640 /var/lib/suricata/rules/

        log  "Set the ownership for Suricata directories"
        chown -R suricata:suricata /var/lib/suricata /etc/suricata /var/log/suricata
        log " Reload systemd daemon to recognize new service"
        log "Reloading systemd daemon..."
        systemctl daemon-reload || error_exit "Failed to reload systemd configuration."
        log "enabling tgreen hunting source"
        suricata-update enable-source tgreen/hunting
        suricata-update update-sources
        log "Enable and start Suricata service"
        systemctl unmask suricata

        log "Enabling Suricata service to start on boot..."
        systemctl enable suricata
        log "updating surircata rules"
        suricata-update

        log "Testing Suricata configuration..."
        suricata -T -c /etc/suricata/suricata.yaml -v|| error_exit "Suricata configuration test failed."
        log "Suricata is configured in permissive IDS mode on interface '$DEFAULT_INTERFACE' with auto cores."
        log "Starting Suricata service..."
        systemctl start suricata.service || error_exit "Failed to start Suricata service."
        log "Suricata installation and configuration completed successfully."
        log "intalling log watch monitor"
   
    cp ./suricata_watchdog.py /var/lib/strongswan/ || error_exit "Failed to copy watchdog script"
    log " Create the suricata_watchdog directory"
    mkdir -p /var/lib/suricata_watchdog || error_exit "failed to create suricata_watchdog directory"
    mkdir -p /var/log/suricata_watchdog_actions || error_exit "failed to create suricata_watchdog_actions directory"
    chown -R root:root /var/lib/suricata_watchdog || error_exit "failed to change ownership of suricata_watchdog directory"
    cat <<EOF | tee /etc/systemd/system/suricata_watchdog.service  > /dev/null
[Unit]
Description=Suricata Watchdog Service
After=network.target suricata.service

[Service]
Type=simple
User=root
ExecStart=/usr/bin/python3 /var/lib/strongswan/suricata_watchdog.py
Restart=on-failure
RestartSec=5s

[Install]
WantedBy=multi-user.target

EOF
        log "creating watchdog service"

        systemctl daemon-reload
        log  "starting watchdog service"
        systemctl enable suricata_watchdog || error_exit "failed to enable watchdog service"
        systemctl start suricata_watchdog  || error_exit "failed to start watchdog"
        systemctl status suricata_watchdog --no-pager
        log "validating alerting"
        curl http://testmynids.org/uid/index.html
        grep 2100498 /var/log/suricata/fast.log
        jq 'select(.alert .signature_id==2100498)' /var/log/suricata/eve.json
        log " Add cron job to update Suricata rules daily at 1 AM and reload them"
        (crontab -l 2>/dev/null; echo "0 1 * * * /usr/bin/suricata-update && pkill -HUP suricata") | crontab -
}



function wait_for_apt_lock() {
    local retries=10
    local wait_time=5
    local count=0
    while fuser /var/lib/dpkg/lock-frontend >/dev/null 2>&1 || fuser /var/lib/dpkg/lock >/dev/null 2>&1; do
        if [ $count -ge $retries ]; then
            log "Could not acquire dpkg lock after $((retries*wait_time)) seconds. Aborting."
            return 1
        fi
        log "Another apt process is running. Waiting $wait_time seconds (attempt $((count+1))/$retries)."
        sleep $wait_time
        count=$((count+1))
    done
    return 0
}


harden-system() {
    log "Hardening the system..."
    export APT_LISTBUGS_FRONTEND=none
 
    log "Adding rkhunter cron jobs..."
    (crontab -l 2>/dev/null; echo "30 3 */3 * * /usr/bin/rkhunter --update") | crontab -
    (crontab -l 2>/dev/null; echo "0 4 */3 * * /usr/bin/rkhunter --check --sk --report-warnings-only --appendlog") | crontab -
    (crontab -l 2>/dev/null; echo "0 5 */3 * * /usr/bin/rkhunter --propupd") | crontab -

  
    log "Starting process accounting..."
    if systemctl start acct; then
        systemctl enable acct || error_exit "Failed to enable acct service."
    else
        error_exit "Failed to start acct service."
    fi

  
    if ! wait_for_apt_lock; then
        error_exit "Could not acquire apt lock. Another process is using apt. Run the script again once apt is free."
    fi


    log "Ensuring AppArmor is installed and enforced..."

    if ! dpkg-query -W apparmor >/dev/null 2>&1; then
        log "Installing AppArmor..."
        apt-get install -y apparmor apparmor-utils || error_exit "Failed to install AppArmor packages."
    fi

    if command -v apparmor_status >/dev/null 2>&1; then
        log "Enforcing AppArmor profiles..."
        for profile_path in /etc/apparmor.d/*; do
            if [[ -f $profile_path && $profile_path != *"disable"* ]]; then
                aa-enforce "$profile_path" 2>/dev/null || log "Could not enforce AppArmor profile: $profile_path"
            fi
        done
        systemctl enable apparmor || log "Failed to enable AppArmor."
        systemctl start apparmor || log "Failed to start AppArmor."
    else
        log "AppArmor is not available on this system. Skipping AppArmor enforcement steps."
    fi
  


    log "Configuring core dump settings..."
    LIMITS_CONF="/etc/security/limits.conf"
    CORE_DUMP_SETTING="* hard core 0"

    if grep -Fxq "$CORE_DUMP_SETTING" "$LIMITS_CONF"; then
        echo "Core dump setting already exists in $LIMITS_CONF"
    else
        echo "Adding core dump setting to $LIMITS_CONF..."
        echo "$CORE_DUMP_SETTING" | tee -a "$LIMITS_CONF" >/dev/null
        if [ $? -eq 0 ]; then
            echo "Successfully added core dump setting to $LIMITS_CONF"
        else
            echo "Failed to add core dump setting. Please check your permissions."
        fi
    fi


    log "Configuring default umask..."
    if grep -q "^UMASK" /etc/login.defs; then
        current_umask=$(grep "^UMASK" /etc/login.defs | awk '{print $2}')
        if [ "$current_umask" != "027" ]; then
            sed -i 's/^UMASK.*/UMASK 027/' /etc/login.defs
        fi
    else
        echo "UMASK 027" | tee -a /etc/login.defs > /dev/null
    fi
    echo "Default umask in /etc/login.defs is now 027."
    
    
    log "Configuring password hashing rounds..."
    sed -i '/^SHA_CRYPT_MIN_ROUNDS/c\SHA_CRYPT_MIN_ROUNDS 5000' /etc/login.defs
    sed -i '/^SHA_CRYPT_MAX_ROUNDS/c\SHA_CRYPT_MAX_ROUNDS 50000' /etc/login.defs

   
    log "Installing and configuring PAM module for password strength testing (pam_pwquality)..."
    if ! wait_for_apt_lock; then
        error_exit "Could not acquire apt lock. Another process is using apt. Run the script again once apt is free."
    fi
    apt-get install -y libpam-pwquality
    if ! grep -q "pam_pwquality.so" /etc/pam.d/common-password; then
        sed -i '/^password.*pam_unix\.so/ s/$/ remember=5 minlen=12/' /etc/pam.d/common-password
        sed -i '/^password.*pam_unix\.so/ i\password required pam_pwquality.so retry=3' /etc/pam.d/common-password
    fi

    log "Configuring minimum password age..."
    sed -i '/^PASS_MIN_DAYS/c\PASS_MIN_DAYS 1' /etc/login.defs

 
    log "Installing and configuring system update tools..."
    if ! wait_for_apt_lock; then
        error_exit "Could not acquire apt lock. Another process is using apt. Run the script again once apt is free."
    fi
    apt-get install -y unattended-upgrades apt-listchanges apticron apt-transport-https apt-show-versions apt-listbugs
    log "Configuring apt-listchanges to be non-interactive..."
    debconf-set-selections <<< 'apt-listchanges apt-listchanges/which string both'
    debconf-set-selections <<< 'apt-listchanges apt-listchanges/email-address string root'
    debconf-set-selections <<< 'apt-listchanges apt-listchanges/frontend select mail'
    dpkg-reconfigure -f noninteractive apt-listchanges
    dpkg-reconfigure -f noninteractive apticron

    log "Updating the system packages..."
    if ! wait_for_apt_lock; then
        error_exit "Could not acquire apt lock. Another process is using apt. Run the script again once apt is free."
    fi
    apt-get update
    apt-get upgrade -y
    apt-get dist-upgrade -y

    log "Purging old/removed packages..."
    apt-get autoremove --purge -y

 
    log "Installing and enabling sysstat..."
    if ! wait_for_apt_lock; then
        error_exit "Could not acquire apt lock. Another process is using apt. Run the script again once apt is free."
    fi
    apt-get install -y sysstat
    sed -i 's/ENABLED="false"/ENABLED="true"/g' /etc/default/sysstat
    systemctl enable sysstat
    systemctl start sysstat

 
    log "Installing and configuring auditd if available..."
    if ! wait_for_apt_lock; then
        error_exit "Could not acquire apt lock. Another process is using apt. Run the script again once apt is free."
    fi
    if apt-get install -y auditd audispd-plugins; then
    
        if systemctl status auditd >/dev/null 2>&1; then
            log "Ensuring auditd is enabled and started for system auditing..."
            systemctl enable auditd || log "Failed to enable auditd service."
            systemctl start auditd || log "Failed to start auditd service."
     
            log "Ensuring auditd has a basic ruleset..."
            if [ ! -f /etc/audit/rules.d/99-default.rules ]; then
                mkdir -p /etc/audit/rules.d
                cat <<EOF | tee /etc/audit/rules.d/99-default.rules >/dev/null
-w /etc/passwd -p wa -k passwd_changes
-w /etc/shadow -p wa -k shadow_changes
EOF
                augenrules --load
            fi
            systemctl restart auditd || log "Failed to restart auditd service after applying basic rules."
        else
            log "auditd service is not available, skipping enabling and starting it."
        fi
    else
        log "auditd installation failed or not available, skipping auditd configuration."
    fi

    log "Blacklisting protocols that are typically not needed..."
    if [ ! -f /etc/modprobe.d/blacklist.conf ]; then
        touch /etc/modprobe.d/blacklist.conf
    fi
    for module in dccp sctp rds tipc; do
        if ! grep -q "blacklist $module" /etc/modprobe.d/blacklist.conf; then
            echo "blacklist $module" | tee -a /etc/modprobe.d/blacklist.conf
        fi
    done


    log "Disabling firewire modules if not needed..."
    for module in firewire-core firewire-ohci firewire-sbp2; do
        if ! grep -q "blacklist $module" /etc/modprobe.d/blacklist.conf; then
            echo "blacklist $module" | tee -a /etc/modprobe.d/blacklist.conf
        fi
    done


    log "Updating initramfs to apply module blacklists and other changes..."
    update-initramfs -u || error_exit "Failed to update initramfs"


    log "Installing and configuring AIDE..."
    if ! wait_for_apt_lock; then
        error_exit "Could not acquire apt lock. Another process is using apt. Run the script again once apt is free."
    fi
    apt-get install -y aide
    if command -v aide >/dev/null 2>&1; then
        aideinit -c /etc/aide/aide.conf
        mv /var/lib/aide/aide.db.new /var/lib/aide/aide.db
   
        if ! grep -q 'aide' /etc/crontab; then
            echo "0 3 * * * root /usr/bin/aide.wrapper --config /etc/aide/aide.conf --check" | tee -a /etc/crontab > /dev/null
        fi
   
        if ! grep -q '^Checksums = sha512' /etc/aide/aide.conf; then
            echo "Checksums = sha512" | tee -a /etc/aide/aide.conf
        fi
        echo "AIDE installation and setup complete."
    else
        log "AIDE command not found. Possibly not installed or not supported on this system."
    fi

 
    log "Configuring sshd_config..."

    cat << EOF | tee /etc/ssh/sshd_config
# Secure SSH Configuration
Port 22
Protocol 2
HostKey /etc/ssh/ssh_host_rsa_key
HostKey /etc/ssh/ssh_host_ecdsa_key
HostKey /etc/ssh/ssh_host_ed25519_key
KeyRegenerationInterval 1h
ServerKeyBits 2048
SyslogFacility AUTH
LogLevel VERBOSE
LoginGraceTime 1m
PermitRootLogin no
StrictModes yes
MaxAuthTries 3
MaxSessions 2
PubkeyAuthentication yes
AuthorizedKeysFile .ssh/authorized_keys
PasswordAuthentication no
PermitEmptyPasswords no
HostbasedAuthentication no
ChallengeResponseAuthentication no
KbdInteractiveAuthentication no
PrintMotd no
UsePAM yes
AllowTcpForwarding no
AllowAgentForwarding no
X11Forwarding no
ClientAliveInterval 300
ClientAliveCountMax 2
TCPKeepAlive no
Banner /etc/ssh/ssh_banner
Ciphers aes256-ctr,aes192-ctr,aes128-ctr
KexAlgorithms diffie-hellman-group-exchange-sha256
MACs hmac-sha2-256,hmac-sha2-512
Subsystem sftp  /usr/lib/openssh/sftp-server
EOF

    chmod 600 /etc/ssh/sshd_config
    if systemctl restart ssh; then
        log "SSHD configuration rewritten and SSH service restarted."
    else
        error_exit "Failed to restart SSH service with new configuration. Check /etc/ssh/sshd_config for errors."
    fi

    log "Installing Fail2Ban for SSH"
    if ! wait_for_apt_lock; then
        error_exit "Could not acquire apt lock. Another process is using apt. Run the script again once apt is free."
    fi
    apt-get install -y fail2ban || error_exit "Failed to install Fail2Ban."

    systemctl enable fail2ban
    systemctl restart fail2ban || error_exit "Failed to restart Fail2Ban service."

    echo "Configuring Fail2Ban to add banned IPs to nftables set 'blacklisted_ips' with a timeout..."
    cat << EOF | tee /etc/fail2ban/jail.local
bantime = 1h
findtime = 10m
findtime = 10m
maxretry = 5

[sshd]
enabled = true
port = ssh
filter = sshd
logpath = /var/log/auth.log
action = nftables[name=sshd, port=ssh, protocol=tcp, chain=input, set=blacklisted_ips]
EOF
    chmod 666 /var/run/fail2ban/fail2ban.sock || log "Failed to set permissions on /var/run/fail2ban/fail2ban.sock"
    echo "Fail2Ban configured to use the nftables set 'blacklisted_ips' for SSH bans with a timeout of 10 minutes."
    echo "Restarting Fail2Ban service to apply changes..."
    systemctl restart fail2ban

    echo "Checking Fail2Ban status for the sshd jail..."
    fail2ban-client status sshd || log "Failed to retrieve Fail2Ban status. Please check fail2ban is running."


    log "Setting legal banners..."
    cat << 'EOF' | tee /etc/issue
-----------------------------------------------------------------------
              Authorized access only!
-----------------------------------------------------------------------

If you are not authorized to access or use this system, disconnect now!

Unauthorized access or use of this system is strictly prohibited 
        and subject to criminal prosecution.
EOF

    cat << 'EOF' | tee /etc/issue.net
-----------------------------------------------------------------------
              Authorized access only!
-----------------------------------------------------------------------

If you are not authorized to access or use this system, disconnect now!

Unauthorized access or use of this system is strictly prohibited 
            and subject to criminal prosecution.
EOF

  
    log "Updating 'locate' database..."
    if [ -f /usr/bin/updatedb ]; then
        updatedb
    fi

    if ! crontab -l 2>/dev/null | grep -q 'debsums'; then
        log "Configuring debsums regular checks..."
        (crontab -l 2>/dev/null; echo "0 4 * * * /usr/bin/debsums --all --changed") | crontab -
    fi


    log "Restricting compiler usage to root only..."
    for compiler in /usr/bin/gcc /usr/bin/g++ /usr/bin/cc /usr/bin/gcc-*; do
        if [ -f "$compiler" ] && [ -x "$compiler" ]; then
            chmod 700 "$compiler"
        fi
    done


    log "Applying additional sysctl hardening settings..."
    echo "net.ipv4.conf.all.log_martians = 1" | tee -a /etc/sysctl.conf
    echo "net.ipv4.icmp_ignore_bogus_error_responses = 1" | tee -a /etc/sysctl.conf
    echo "net.ipv4.tcp_syncookies = 1" | tee -a /etc/sysctl.conf
    echo "net.ipv4.ip_no_pmtu_disc = 0" | tee -a /etc/sysctl.conf

   
    if modprobe -q tcp_bbr 2>/dev/null && printf '%s\n%s' "4.20" "$(uname -r)" | sort -C -V; then
        sysctl -w net.ipv4.tcp_congestion_control=bbr 2>/dev/null
    fi
    sysctl --system
    sysctl -p



        echo "Configuring GRUB password..."

            hashed_password=$(echo -e "$GRUB_PSSWD\n$GRUB_PSSWD" | grub-mkpasswd-pbkdf2 | awk '/PBKDF2 hash of your password is/ {print $NF}')
            
            if [ -z "$hashed_password" ]; then
                echo "Error: Could not generate PBKDF2 hash for GRUB password. Ensure grub-mkpasswd-pbkdf2 output is correct."
                exit 1
            fi

            cp /etc/grub.d/40_custom /etc/grub.d/40_custom.bak

       
            sed -i '/set superusers/d' /etc/grub.d/40_custom
            sed -i '/password_pbkdf2/d' /etc/grub.d/40_custom

            bash -c "cat > /etc/grub.d/40_custom" <<EOF
#!/bin/sh
exec tail -n +3 \$0
# Custom GRUB password protection

set superusers="root"
password_pbkdf2 root ${hashed_password}
EOF

   
            chmod +x /etc/grub.d/40_custom

            sed -i "/\$os/s/grub_quote)'/grub_quote)' --unrestricted/" /etc/grub.d/10_linux


            sed -i '/GRUB_DEFAULT/d' /etc/default/grub
            echo "GRUB_DEFAULT=0" | tee -a /etc/default/grub > /dev/null

            sed -i '/GRUB_TIMEOUT/d' /etc/default/grub
            echo "GRUB_TIMEOUT=5" | tee -a /etc/default/grub > /dev/null

            sed -i '/GRUB_TIMEOUT_STYLE/d' /etc/default/grub
            echo "GRUB_TIMEOUT_STYLE=menu" | tee -a /etc/default/grub > /dev/null

        
            update-grub
            if [ $? -ne 0 ]; then
                echo "Warning: Failed to update GRUB configuration. Check /etc/grub.d/40_custom and grub config for errors."
            else
                echo "GRUB password set and GRUB configuration updated."
            fi

    if command -v syslog-ng_config >/dev/null 2>&1; then
        log "Running syslog-ng configuration function..."
        syslog-ng_config
    fi

    echo "System hardening steps are completed."
}

enable_unattended_security_updates() {
    log "Enabling unattended security updates..."

    # Ensure the package is installed
    apt-get update
    apt-get install -y unattended-upgrades

    # Configure unattended-upgrades
    dpkg-reconfigure -fnoninteractive unattended-upgrades

    # Optional: Enable periodic updates
    echo "APT::Periodic::Update-Package-Lists \"1\";" > /etc/apt/apt.conf.d/20auto-upgrades
    echo "APT::Periodic::Unattended-Upgrade \"1\";" >> /etc/apt/apt.conf.d/20auto-upgrades
    setfacl -m u:ocsp:r /etc/swanctl/ocsp/ocsp-key.pem
    log "Unattended security updates enabled."
}


syslog-ng_config() {
    LOGROTATE_CONFIG="/etc/logrotate.d/custom_logs"
    load_config

    if ! wait_for_apt_lock; then
        error_exit "Could not acquire apt lock. Another process is using apt. Run the script again once apt is free."
    fi

  
    log "Installing syslog-ng..."
    apt-get install -y syslog-ng-core || error_exit "Failed to install syslog-ng-core."
    
    

  
    cat << EOF  | tee /etc/syslog-ng/syslog-ng.conf > /dev/null
@version: 3.38
@include "scl.conf"

# Syslog-ng configuration file, compatible with default Debian syslogd installation.

# First, set some global options.
options { 
    chain_hostnames(off); 
    flush_lines(0); 
    use_dns(no); 
    use_fqdn(no);
    dns_cache(no); 
    owner("root"); 
    group("adm"); 
    perm(0640);
    stats_freq(0); 
    bad_hostname("^gconfd$");
};

########################
# Sources
########################
source s_src {
    system();
    internal();
};

# Source for specific logs
source s_specific_logs {
    file("/var/log/suricata/eve.json");
    file("/var/log/suricata/fast.log");
    file("/var/log/suricata/suricata.log");
    file("/var/log/suricata_watchdog_actions/actions.log");
    file("/var/log/swanctl_user_check.log");
};

########################
# Destinations
########################
# Arctic Wolf log forwarding
destination d_arcticwolf {
    tcp("${ARCTICWOLF_IP}" port(514));
};

########################
# Log paths
########################
# Arctic Wolf log forwarding paths
log {
    source(s_src);
    destination(d_arcticwolf);
};

log {
    source(s_specific_logs);
    destination(d_arcticwolf);
};

EOF

    if [ -f "/etc/logrotate.d/suricata" ]; then
        log "Suricata logrotate file found (/etc/logrotate.d/suricata). Skipping Suricata logs configuration to avoid duplicates."
    else
      
        log "Configuring log rotation for specific logs..."
        if [ ! -f "$LOGROTATE_CONFIG" ]; then
            touch "$LOGROTATE_CONFIG"
        fi

        for log_file in /var/log/suricata/*.log /var/log/suricata_watchdog_actions/actions.log /var/log/okta-group-verify.log /var/log/swanctl_user_check.log; do
            sed -i "\|$log_file|d" "$LOGROTATE_CONFIG"
        done

  
        cat <<EOL | tee -a "$LOGROTATE_CONFIG"
/var/log/suricata/*.log
/var/log/suricata_watchdog_actions/actions.log
/var/log/okta-group-verify.log
/var/log/ocsp-responder.log
/var/log/swanctl_user_check.log {
    weekly
    rotate 4
    compress
    missingok
    notifempty
    create 0640 root adm
    sharedscripts
    postrotate
        # Reload syslog-ng only if it's running
        if systemctl is-active syslog-ng >/dev/null; then
            systemctl reload syslog-ng || log "Failed to reload syslog-ng service."
        fi
    endscript
}
EOL

        echo "Weekly log rotation configured for Suricata, suricata_watchdog_actions, and okta-group-verify logs."
    fi


    log "Validating syslog-ng configuration using 'syslog-ng -s'..."
    if syslog-ng -s; then
        log "Syslog-ng configuration validated successfully."
  
        if systemctl is-enabled syslog-ng >/dev/null 2>&1; then
            if systemctl restart syslog-ng; then
                echo "Syslog-ng restarted successfully."
            else
                log "Syslog-ng failed to restart. Check syslog-ng configuration or logs for details."
            fi
        fi
    else
        log "Syslog-ng configuration validation failed. Check /etc/syslog-ng/syslog-ng.conf for errors."
    fi


    if command -v logrotate >/dev/null 2>&1; then
        logrotate -f /etc/logrotate.conf
        echo "Logrotate executed for initial testing."
    else
        log "logrotate command not found, skipping logrotate test."
    fi

    echo "Logging configuration complete."
}

ssh_keycheck() {
    log "Checking for existing SSH keys..."
    KEY_INSTALLED="false"
    if [ -f "/root/.ssh/authorized_keys" ] && [ -s "/root/.ssh/authorized_keys" ]; then
        KEY_INSTALLED="true"
    else
        for user_home in /home/*; do
            if [ -d "$user_home" ] && [ -f "$user_home/.ssh/authorized_keys" ] && [ -s "$user_home/.ssh/authorized_keys" ]; then
                KEY_INSTALLED="true"
                break
            fi
        done
    fi
}

update_progress() {
    local progress="$1"
    local message="$2"
    echo "$progress" > /tmp/install_progress
    echo "$message" > /tmp/install_message
}

loading_screen() {
    local pid=$1
    local progress_file="/tmp/install_progress"
    local message_file="/tmp/install_message"

    echo "0" >"$progress_file"
    echo "Starting installation..." >"$message_file"

    dialog --title "Installing StrongSwan VPN Gateway" \
        --gauge "Starting installation..." 10 70 0 < <(
            while kill -0 "$pid" 2>/dev/null; do
                progress=$(cat "$progress_file" 2>/dev/null || echo "0")
                message=$(cat "$message_file" 2>/dev/null || echo "Working...")
                echo "$progress"
                echo "XXX"
                echo "$message"
                echo "XXX"
                sleep 1
            done
            echo 100
        )
}


install() {
    LOG_FILE="/var/log/strongconn.log"  # Define log file for the installation

    update_progress 0 "Starting installation..." 
    log "Starting installation..." >> "$LOG_FILE" 2>&1

    update_progress 5 "Checking prerequisites..." 
    log "Checking for ipcalc..." >> "$LOG_FILE" 2>&1
    if ! command -v ipcalc &>/dev/null; then
        log "ipcalc not found, installing it..." >> "$LOG_FILE" 2>&1
        apt-get update -y >> "$LOG_FILE" 2>&1
        apt-get install -y ipcalc >> "$LOG_FILE" 2>&1 || error_exit "Failed to install ipcalc"
    else
        log "ipcalc found." >> "$LOG_FILE" 2>&1
    fi

    CONFIG_PATH="/etc/strongconn.conf"
    if [ ! -f "$CONFIG_PATH" ]; then
        update_progress 8 "Creating configuration file..."
        log "Configuration file not found. Creating default configuration file..." >> "$LOG_FILE" 2>&1
        cp ./strongconn.conf "$CONFIG_PATH" >> "$LOG_FILE" 2>&1 || error_exit "Failed to copy config to /etc"
        chmod 640 "$CONFIG_PATH" >> "$LOG_FILE" 2>&1 || error_exit "Failed to set permissions on config"
    fi

    update_progress 10 "Setting up directories..." 
    log "Configuration updated. Current settings:" >> "$LOG_FILE" 2>&1
    cat "$CONFIG_PATH" >> "$LOG_FILE" 2>&1
    mkdir -p /var/lib/strongswan >> "$LOG_FILE" 2>&1 || error_exit "Failed to create directory /var/lib/strongswan"

    SCRIPT_SOURCE="${BASH_SOURCE[0]}"
    while [ -h "$SCRIPT_SOURCE" ]; do
        DIR="$(cd -P "$(dirname "$SCRIPT_SOURCE")" >/dev/null 2>&1 && pwd)"
        SCRIPT_SOURCE="$(readlink "$SCRIPT_SOURCE")"
        [[ $SCRIPT_SOURCE != /* ]] && SCRIPT_SOURCE="$DIR/$SCRIPT_SOURCE"
    done

    SCRIPT_DIR="$(cd -P "$(dirname "$SCRIPT_SOURCE")" >/dev/null 2>&1 && pwd)"
    cd "$SCRIPT_DIR" >> "$LOG_FILE" 2>&1 || error_exit "Failed to navigate to script directory: $SCRIPT_DIR"

    update_progress 10 "Running system checks..." 
    log "StrongSwan IKEv2 VPN Gateway Installing..." >> "$LOG_FILE" 2>&1
    check_root >> "$LOG_FILE" 2>&1
    sleep 5
    update_progress 12 "Checking OS and DNS resolution..." 
    check_os >> "$LOG_FILE" 2>&1
    configure_dns >> "$LOG_FILE" 2>&1
    sleep 5
    update_progress 15 "Checking network interfaces..." 
    check_network >> "$LOG_FILE" 2>&1
    check_dns_resolution >> "$LOG_FILE" 2>&1
    sleep 5
    update_progress 20 "Checking kernel modules and loading on boot..."  
    check_and_compile_modules >> "$LOG_FILE" 2>&1
    update_progress 22 "Checking StrongSwan group..." 
    check_strongswan_group >> "$LOG_FILE" 2>&1
    sleep 5
    update_progress 23 "Checking Charon socket permissions..." 
    sleep 5
    check_charon_socket_permissions >> "$LOG_FILE" 2>&1
    update_progress 25 "Installing dependencies & tools..." 
    sleep 10 
    update_progress 30 "Installing dependencies & tools..."
    install_dependencies >> "$LOG_FILE" 2>&1
    update_progress 35 "Compiling StrongSwan..." 
    sleep 10
    update_progress 40 "Compiling StrongSwan..."
    sleep 10
    update_progress 44 "Compiling StrongSwan..."
    compile_strongswan >> "$LOG_FILE" 2>&1
    update_progress 45 "Setting up FRR OSPF..." 
    sleep 5
    setup_frr_ospf >> "$LOG_FILE" 2>&1
    update_progress 50 "Copying files..."
    sleep 3 
    install_helper >> "$LOG_FILE" 2>&1
    update_progress 55 "Initializing PKI..." 
    sleep 5
    init_db >> "$LOG_FILE" 2>&1
    update_progress 57 "Generating CA..." 
    generate_ca >> "$LOG_FILE" 2>&1
    sleep 2  
    update_progress 60 "Installing Ngnix reverse proxy & OCSP responder..."  
    setup_ocsp_responder >> "$LOG_FILE" 2>&1
    update_progress 62 "Generating server CN= $PUBLIC_IP certificate..." 
    generate_server >> "$LOG_FILE" 2>&1
    sleep 2
    update_progress 65 "Configuring nftables & swanctl..." 
    setup_firewalld >> "$LOG_FILE" 2>&1
    configure_swanctl >> "$LOG_FILE" 2>&1
    inject_Banner >> "$LOG_FILE" 2>&1
    sleep 2
    update_progress 66 "Configuring Cockpit..." 
    setup_cockpit >> "$LOG_FILE" 2>&1
    update_progress 67 "Starting Strongswan..." 
    start_vpn >> "$LOG_FILE" 2>&1
    update_progress 68 "Configuring Syslog-ng..." 
    sleep 5

    update_progress 70 "Installing script components..." 
    cd "$SCRIPT_DIR" >> "$LOG_FILE" 2>&1 || error_exit "Failed to return to script directory"
    
    scripts=("strongconn.sh" "tunnel.sh")
    for script in "${scripts[@]}"; do
        src_path="$SCRIPT_DIR/$script"
        dest_path="/usr/bin/$script"
        cp "$src_path" "$dest_path" >> "$LOG_FILE" 2>&1 || error_exit "Failed to copy '$script' to /usr/bin/."
        chmod +x "$dest_path" >> "$LOG_FILE" 2>&1 || error_exit "Failed to set execute permission on '$dest_path'."
        log "Successfully installed '$script' to /usr/bin/." >> "$LOG_FILE" 2>&1
    done

    update_progress 75 "Installing Suricata IDS..." 
    install_suricata >> "$LOG_FILE" 2>&1  # This step takes about 15% of total install time
    sleep 10
    update_progress 80 "Installing Python Script... "
    sleep 2
    update_progress 85 "Configuring Suricata IDS "
    sleep 3
    update_progress 88 "Updating Suricata IDS"
    sleep 10
    update_progress 90 "Installing Cockpit module..." 
    updatedb >> "$LOG_FILE" 2>&1 || error_exit "Failed to update locate database."
    dpkg -i ./strongswan-cockpit-module.deb >> "$LOG_FILE" 2>&1 || {
        log "Failed to install strongswan-cockpit-module.deb. Attempting to fix dependencies." >> "$LOG_FILE" 2>&1
        apt-get install -f -y >> "$LOG_FILE" 2>&1 || error_exit "Failed to fix dependencies." 
        systemctl restart cockpit >> "$LOG_FILE" 2>&1 || error_exit "Failed to restart cockpit service."
    }
    update_progress 92 "Writing Okta profile..." 
    write_okta_profile >> "$LOG_FILE" 2>&1
    sleep 5
    update_progress 95 "Hardening system, enabling unattended security updates..." 
    harden-system >> "$LOG_FILE" 2>&1
    update_progress 98 "Enabling unattended security updates..." 
    enable_unattended_security_updates >> "$LOG_FILE" 2>&1
    sleep 10
        update_progress 99 "Installation complete!" 
        update_progress 100 "Install complete. Press Enter to reboot..."
        log "Installation complete" >> "$LOG_FILE" 2>&1
        dialog --msgbox "Installation complete! Press Enter to reboot..." 8 50
        dialog --clear
        reboot
}


case "$1" in

    -install)

        CONFIG_PATH="/etc/strongconn.conf"
        export TERM=xterm

        # Load the configuration file
        if [ ! -f "$CONFIG_PATH" ]; then
            echo "Configuration file $CONFIG_PATH not found. Exiting."
            
            exit 1
        fi
        

        # Validate the loaded DEFAULT_IP
        DEFAULT_IP=${DEFAULT_IP:-"Not Set"}
        echo "DEFAULT_IP is set to: $DEFAULT_IP"
        echo "DEBUG: TERM=$TERM" >&2
        echo "DEBUG: SHELL=$SHELL" >&2

        # Ensure dialog is installed
    # Ensure dialog is installed
        if ! command -v dialog >/dev/null 2>&1; then
            echo "DEBUG: 'dialog' not found. Installing..."
            export DEBIAN_FRONTEND=noninteractive
            apt-get update -y && apt-get install -y dialog || {
                echo "ERROR: Failed to install 'dialog'. Exiting."
                exit 1
            }
            echo "DEBUG: 'dialog' installed successfully."
            export DEBIAN_FRONTEND=noninteractive
            apt-get update -y && apt-get install -y dialog || {
                echo "ERROR: Failed to install 'dialog'. Exiting."
                
                exit 1
            }
            echo "DEBUG: 'dialog' installed successfully."
        else
            echo "DEBUG: 'dialog' is already installed."
        fi

        
        echo "DEBUG: Running dialog command..." >&2

            VPN_MODE=$(dialog --backtitle "Strongswan Ipsec Gateway Installer" \
            --title "VPN Client Routing Selection" \
            --menu "Choose the VPN Route operating mode:" 15 70 3 \
            1 "NAT Mode - client IP masquerading private pool" \
            2 "Routed Mode - return static to pool required (flat-network)" \
            3 "DHCP Mode - strongSwan DHCP proxies LAN's DHCP server" 2>&1 >/dev/tty)

        if [ -z "$VPN_MODE" ]; then
            echo "No VPN mode selected or dialog failed. Exiting."
            exit 1
        fi

        case $VPN_MODE in
            1) VPN_MODE="NAT" ;;
            2) VPN_MODE="ROUTED" ;;
            3) VPN_MODE="DHCP" ;;
            *)
                echo "Invalid selection: $VPN_MODE"
                exit 1
                ;;
        esac
        # Add VPN_MODE to the config file
        echo "VPN_MODE=\"$VPN_MODE\"" >> "$CONFIG_PATH"
        
        # Ask user if they want to edit the config file
        dialog --backtitle "Strongswan Ipsec Gateway Installer" \
            --yesno "Edit Installer config file now?" 8 50

        
        if [ $? -eq 0 ]; then
            # User chose to edit the config
            if [ -n "$EDITOR" ]; then
                $EDITOR "$CONFIG_PATH" || {
                    echo "Failed to open configuration file in $EDITOR."
                    
                    exit 1
                }
            else
                nano "$CONFIG_PATH" || {
                    echo "Failed to open configuration file in nano."
                    
                    exit 1
                }
            fi
        fi
        
        # Show current config and confirm start
        dialog --backtitle "Strongswan Ipsec Gateway Installer" \
            --title "Review Installer Config" \
            --textbox "$CONFIG_PATH" 20 70

        dialog --backtitle "Strongswan Ipsec Gateway Installer" \
            --yesno "Start Installation?" 8 50

        # Check for SSH keys
        ssh_keycheck
        if [ "$KEY_INSTALLED" != "true" ]; then
            dialog --backtitle "StrongSwan VPN Gateway Setup" \
                --msgbox "No SSH keys found. Please install an SSH key before continuing." 8 50 

            error_exit "No SSH keys found. Please install an SSH key before continuing."
        fi

        # Ensure dialog is installed
        if ! command -v dialog >/dev/null 2>&1; then
            echo "DEBUG: 'dialog' not found. Installing..."
            export DEBIAN_FRONTEND=noninteractive
            apt-get update -y && apt-get install -y dialog || {
                echo "ERROR: Failed to install 'dialog'. Exiting."
                
                exit 1
            }
            echo "DEBUG: 'dialog' installed successfully."
        else
            echo "DEBUG: 'dialog' is already installed."
        fi
        if [ "$KEY_INSTALLED" != "true" ]; then
            dialog --backtitle "StrongSwan VPN Gateway Setup" \
                --msgbox "No SSH keys found. Please install an SSH key before continuing." 8 50 

            error_exit "No SSH keys found. Please install an SSH key before continuing."
        fi
        
        # Start installation with progress bar
        LOG_FILE="/var/log/strongconn.log"
        {
            install >"$LOG_FILE" 
        } &
        installer_pid=$!
        loading_screen $installer_pid
        wait $installer_pid

        
        # failure dialog
        dialog --backtitle "StrongSwan VPN Gateway Setup" \
            --msgbox "Installation Failed /var/log/strongconn.log" 8 50
        ;;
    -debug)
        debug_strongswan
        ;;
    -write-okta-profile)
        write_okta_profile
        ;;
    -switch-config)
        
        if [ -z "$2" ]; then
            error_exit "-switch-config {okta|pubkey|both}."
        fi
        switch_vpn_config "$2"
        write_okta_profile
        ;;
    -check-comp)
        check_and_compile_modules
            log "Module check and compile (if necessary)"
            log "..."
        ;;
    -kernel_updates)
        log "Setting kernel update option from conf"
        kernel-updates
        ;;
    -setup-logging)
        read -p "Are you sure you want to set up syslog-ng? (y/n): " confirm
        if [[ "$confirm" != "y" ]]; then
            log "Setup Aborted."
            exit 0
        fi
        log "setting up syslog-ng"
        syslog-ng_config
        ;;
    -export-cert)
        load_and_export_config
        export_cert_to_p12_tar
        ;;
    -update)
        read -p "Are you sure you want to update StrongSwan? (y/n): " confirm
        if [[ "$confirm" != "y" ]]; then
            log "Update Aborted."
            exit 0
        fi
            if [ -f /usr/local/bin/swanctl ] || [ -f /usr/sbin/swanctl ]; then
        log "StrongSwan with swanctl is already installed."
        cd /usr/src/ || exit
        ls -lah
        log  "stop strongswan service & go to the source directory (i.e., /usr/src/strongswanVERSION) and run 'make uninstall' then run upgrade again." 
        exit 1
      
        else
        log "StrongSwan with swanctl is not installed. proceeding with compile....." |
        backup_config || error_exit "Failed to back up StrongSwan configuration......"
        log "StrongSwan config backup complete."
        log "Invoking Compile Function..."
        compile_strongswan || error_exit "Failed to compile StrongSwan."
        log "StrongSwan installation complete.........."
        check_charon_socket_permissions        
        restore_config || error_exit "Failed to restore StrongSwan configuration."
        log "StrongSwan config back up restored complete........."
        start_vpn
        fi
        ;;
    -harden)
        read -p "Are you sure you want to harden the system? (y/n): " confirm
        if [[ "$confirm" != "y" ]]; then
            log "Hardening Aborted."
            exit 0
        fi
        harden-system
        ;;
    -setup-ospf)
        read -p "Are you sure you want to setup frr? (y/n)" confirm
        if [[ "$confirm" != "y" ]]; then
            log "setting up frr"
            exit 0
        fi
        apt-get install  frr  frr-doc -y
        setup_frr_ospf
        ;;
    -setup-nftables)
        read -p "Are you sure you want to setup nft"
        if [[ "$confirm" != "y" ]]; then
            log "installing nft"
            exit 0
        fi
        apt-get remove firewalld -y
        apt-get install nftables -y
        setup_firewalld 
        ;;
    -syslog-ng)
        read -p "install syslog-ng? (y/n):" confirm
        if [[ "$confirm" != "y" ]]; then
            log "aborted syslog-ng"
            exit 0
        fi
        syslog-ng_config
        ;;
    -install-suricata)
        read -p "Are you sure you want to install Suricata? (y/n): " confirm
        if [[ "$confirm" != "y" ]]; then
            log "Installation Aborted."
            exit 0
        fi
        install_suricata
        log "Installing suricata, updating firewall and installing suricata watchdog service"
        ;;        
     *)   
        error_exit "Computer Says No. Usage: $0 -install |-switch-config <okta><pubkey><both> | -update strongswan |-debug | -check-comp"
        exit 1
        ;;
esac
log "------------------------------------------------------------------------------------"
log     "\o/.-.-.-.-.-.-.-.-.-.\o/\o/.-.-.-.-.-.-.-.-.-.\o/\o/.-.-.-.-.-.-.-.-.-.\o/"
log "------------------------------------------------------------------------------------"