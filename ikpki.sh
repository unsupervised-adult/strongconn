#!/bin/bash
#
#############################################################################@#
# THIS SCRIPT IS PROVIDED AS IS WITH NO WARRANTY OR SUPPORT
# The author is not responsible for any damage or loss caused by the use of this script
# Use at your own risk
###############################################################################
# IKEv2-Okta PKI Management Script
###############################################################################
#
# Description:
#   This script manages PKI (Public Key Infrastructure) operations for IKEv2-Okta
#   integration, including certificate creation and management.
#
# Author: Felix C Frank
# Contact: felix.c.frank@proton.me
# Version: 1.0
# Created: 2024
#
# Environment:
#   Designed for Debian-based virtualized environments:
#   - AWS
#   - VMware
#   - Proxmox
#
# Usage:
# PKI Management:
#   check           - Check environment and dependencies for PKI operations
#   rebuild-crl     - Rebuild CRL database index.txt and number files from existing certificates (use with caution)
#
# Server Certificates:
#   generate-ca         - Create & Replace Certificate Authority (CA) replaces existing CA root key & certificate invalidating all existing certificates
#   generate-server     - Generate VPN CN=IP & SAN=IP server certificate pubkey auth 
#   generate-ocsp-cert  - Create OCSP responder CN=IP certificate for OCSP validation run once after CA generation
#   generate-csr DNS_NAME TYPE  - Generate CSR (internal|third-party) for CSR to be signed by third-party CA for production
#   generate-custom-server      - Generate server CN=DNS & SAN=DNS name certificate from CA for testing okta integration
#
# Client Certificates:
#   import-csv CSV_FILE          - Import client certificates from CSV file  basic csv format: email, duration
#   generate-client EMAIL MONTHS - Create client certificate & set lifetime in months (default: 12)
#   revoke-client EMAIL          - Revoke client certificate full crl update required after revocation
#   export-bundle EMAIL          - Export client certificate bundle with ca client cert, key p12 bundle certificates.
#                                  client installers powershell script for windows sswan for android and mobileconfig for ios
#                                  bundle is only required for pubkey auth
#
# CRL Management:
#  to initialize the CRL system, add new certificates, and revoke existing ones.
#  generate-crl OPTION
#        Options:
#          full
#             Generates new CRL updates the CRL index & restarts ocsp responder (run after adding or revoking certificates (a cron job is set to run every 17 days to keep crl updated)
#          init
#            Initializes the CRL environment, setting up necessary configurations. (do not run if you have existing certificates)
#          add CERT_PATH
#             Adds a new certificate to the CRL from the provided CERT_PATH.  (this is automatically done by generate-client)
#          revoke CERT_NAME [REASON]
#             Revokes the certificate identified by CERT_NAME with an optional REASON
#          Revocation Reasons: 
#                              1) superseded 2) keyCompromise 
#                              3) affiliationChanged 4) cessationOfOperation 
#                              5) certificateHold
# Maintenance:
#  list            - List all certificates
#  set-permissions - Fix permissions for /opt/pki /etc/swanctl & /etc/ngnix/ to validate symlinks and replace them if necessary
#                    function also sets ACLs for strongswan, ocsp, and nginx  to access necessary files and directories                 
#
# Dependencies:
#   - OpenSSL
#   - Standard Unix tools
#
# Notes:
#   
#   - Must be run with appropriate privileges
#   - rebuild-crl should be run with caution and as a last resort
#   - init generate-crl init generate CA are destructive operations
#     and will overwrite existing files & they are meant to be run once by initial setup
#     or if you totally want to reset the PKI environment.
#
# Author: Felix C Frank 2024
# Version: 0.9
# Created: 27-12-24
## feedback mailto:felix.c.frank@proton.me
###############################################################################
CONFIG_PATH="/etc/strongconn.conf"

log() {
    printf "%s - %s\n" "$(date +'%Y-%m-%d %H:%M:%S')" "$1"
}

error_exit() {
    printf "Error: %s\n" "$1" >&2
    exit 1
}

truncate_string() {
    local str="$1"
    local maxlen="$2"
    if [[ "${#str}" -gt "$maxlen" ]]; then
        echo "${str:0:$maxlen}"
    else
        echo "$str"
    fi
}

load_config() {
    if [[ -f "$CONFIG_PATH" ]]; then
        source "$CONFIG_PATH"
    else
        error_exit "Configuration file not found at $CONFIG_PATH"
    fi

#Validate required variables
    [[ -z "$CERT_DIR" ]] && error_exit "CERT_DIR is not set in the configuration file."
    [[ -z "$PRIVATE_DIR" ]] && error_exit "PRIVATE_DIR is not set in the configuration file."
    [[ -z "$CA_DIR" ]] && error_exit "CA_DIR is not set in the configuration file."
    [[ -z "$CRL_DIR" ]] && error_exit "CRL_DIR is not set in the configuration file."
    [[ -z "$SRL_DIR" ]] && error_exit "SRL_DIR is not set in the configuration file."
    [[ -z "$CA_NAME" ]] && error_exit "CA_NAME is not set in the configuration file."
    [[ -z "$SERVER_CERT" ]] && error_exit "SERVER_CERT is not set in the configuration file."
    [[ -z "$SERVER_KEY" ]] && error_exit "SERVER_KEY is not set in the configuration file."
    [[ -z "$PUBLIC_IP" ]] && error_exit "PUBLIC_IP is not set in the configuration file."
    [[ -z "$DNS_NAME" ]] && error_exit "DNS_NAME is not set in the configuration file."
    [[ -z "$OCSP_DIR" ]] && error_exit "OCSP_DIR is not set in the configuration file."
    [[ -z "$CA_CERT" ]] && error_exit "CA_CERT is not set in the configuration file."
    [[ -z "$CA_KEY" ]] && error_exit "CA_KEY is not set in the configuration file."
    [[ -z "$PFX_PASSWORD" ]] && error_exit "PFX_PASSWORD is not set in the configuration file."     
    [[ -z "$SRL_FILE" ]] && error_exit "SRL_FILE is not set in the configuration file." 
    [[ -z "$VPN_DURATION" ]] && error_exit "VPN_DURATION is not set in the configuration file."
    [[ -z "$CRL_DURATION" ]] && error_exit "CRL_DURATION is not set in the configuration file."
    [[ -z "$OCSP_PORT" ]] && error_exit "OCSP_PORT is not set in the configuration file."
    [[ -z "$OCSP_KEY" ]] && error_exit "OCSP_KEY is not set in the configuration file."
    [[ -z "$OCSP_CERT" ]] && error_exit "OCSP_CERT is not set in the configuration file."

#Additional variables required for CA generation
    [[ -z "$COUNTRY" ]] && error_exit "COUNTRY is not set in the configuration file."
    [[ -z "$STATE" ]] && error_exit "STATE is not set in the configuration file."
    [[ -z "$CITY" ]] && error_exit "CITY is not set in the configuration file."
    [[ -z "$ORGANIZATION" ]] && error_exit "ORGANIZATION is not set in the configuration file."
    [[ -z "$ORG_UNIT" ]] && error_exit "ORG_UNIT is not set in the configuration file."
    [[ -z "$CA_DURATION" ]] && error_exit "CA_DURATION is not set in the configuration file."
    

        export CERT_DIR="$CERT_DIR"
        export PRIVATE_DIR="$PRIVATE_DIR"
        export CA_DIR="$CA_DIR"
        export CRL_DIR="$CRL_DIR"
        export SRL_DIR="$SRL_DIR"
        export CA_NAME="$CA_NAME"
        export SERVER_CERT="$SERVER_CERT"
        export SERVER_KEY="$SERVER_KEY"
        export PUBLIC_IP="$PUBLIC_IP"
        export DNS_NAME="$DNS_NAME"
        export OCSP_DIR="$OCSP_DIR"
        export CA_CERT="$CA_CERT"
        export CA_KEY="$CA_KEY"
        export PFX_PASSWORD="$PFX_PASSWORD"
        export COUNTRY="$COUNTRY"
        export STATE="$STATE"
        export CITY="$CITY"
        export ORGANIZATION="$ORGANIZATION"
        export ORG_UNIT="$ORG_UNIT"
        export CA_DURATION="$CA_DURATION"

}


print_variables() {
    log "Configuration Variables:"

    log "CERT_DIR: $CERT_DIR"
    log "PRIVATE_DIR: $PRIVATE_DIR"
    log "CA_DIR: $CA_DIR"
    log "CRL_DIR: $CRL_DIR"
    log "SRL_DIR: $SRL_DIR"
    log "CA_NAME: $CA_NAME"
    log "SERVER_CERT: $SERVER_CERT"
    log "SERVER_KEY: $SERVER_KEY"
    log "DNS_NAME: $DNS_NAME"
    log "PUBLIC_IP: $PUBLIC_IP"
}




check_directories() {
    load_config
    log "Ensuring necessary directories exist..."

#Create parent directories first with proper permissions
    mkdir -p "/opt/pki" || error_exit "Failed to create pki directory"
    chmod 755 "/opt/pki"
    mkdir -p "/etc/swanctl" || error_exit "Failed to create swanctl directory"
    mkdir -p "/etc/ssl" || error_exit "Failed to create ssl directory"

#Create specific directories with proper ownership and permissions
    mkdir -p "$CERT_DIR" || error_exit "Failed to create x509 directory $CERT_DIR"
    mkdir -p "$PRIVATE_DIR" || error_exit "Failed to create private directory $PRIVATE_DIR"
    chown root:root "$PRIVATE_DIR"
    chmod 700 "$PRIVATE_DIR"
    mkdir -p "$CA_DIR" || error_exit "Failed to create ca directory $CA_DIR"
    mkdir -p "$CRL_DIR" || error_exit "Failed to create crl directory $CRL_DIR"
    mkdir -p "$SRL_DIR" || error_exit "Failed to create srl directory $SRL_DIR"
    mkdir -p "$SERVER_CERT" || error_exit "Failed to create server cert directory $SERVER_CERT"
    mkdir -p "$SERVER_KEY" || error_exit "Failed to create server key directory $SERVER_KEY"

#Set appropriate permissions
    chmod 755 "/opt/pki" "$CERT_DIR" "$CA_DIR" "$CRL_DIR" "$SRL_DIR" "$SERVER_CERT"
    chmod 700 "$PRIVATE_DIR" "$SERVER_KEY"

    local additional_dirs=(
        "/etc/swanctl/ocsp"
        "/etc/swanctl/x509ocsp"
        "/etc/swanctl/x509aa"
        "/etc/swanctl/x509ac"
        "/etc/swanctl/x509crl"
        "/etc/swanctl/pubkey"
        "/etc/swanctl/rsa"
        "/etc/swanctl/ecdsa"
        "/etc/swanctl/bliss"
        "/etc/swanctl/pkcs8"
        "/etc/swanctl/pkcs12"
        "/opt/pki"
        "/opt/pki/private"
        "/opt/pki/x509"
        "/var/lib/strongswan"
        "/var/lib/strongswan/tmp"
    )

#Create additional directories required for StrongSwan
    for dir in "${additional_dirs[@]}"; do
        mkdir -p "$dir" || error_exit "Failed to create directory $dir"
    done


}

check_environment() {
    log "checking environment..."
#Check required commands
    for cmd in openssl certutil pk12util tar dig wget; do
        command -v "$cmd" >/dev/null 2>&1 || error_exit "$cmd is not installed"
    done
    command -v wget >/dev/null 2>&1 || error_exit "wget is not installed"

    log "All necessary commands are available"

    check_directories
}

set_permissions() {
    log "Setting permissions, ACLs, and validating symlinks for /opt/pki and /etc/swanctl..."

#Base ownership and permissions
    chown -R root:root /opt/pki /etc/swanctl
    chmod 751 /etc/swanctl
    chmod 750 /etc/swanctl/private
    chmod 751 /etc/swanctl/x509
    chmod 751 /etc/swanctl/x509ca
    chmod 751 /etc/swanctl/x509crl
    chmod 751 /etc/swanctl/crls
    chmod 751 /etc/swanctl/conf.d
    chmod 751 /etc/swanctl/ocsp
    chmod 750 /opt/pki/private
    chmod 755 /opt/pki/x509

#Apply ACLs for StrongSwan
    setfacl -Rm g:strongswan:rx /etc/swanctl || log "Failed to set ACL for StrongSwan on /etc/swanctl"
    setfacl -Rm g:strongswan:r /etc/swanctl/private /opt/pki/x509/ca.pem /opt/pki/x509/server.pem /opt/pki/x509/ocsp.pem /opt/pki/private/server-key.pem || log "Failed to set ACL for StrongSwan on private keys and certificates"

#Apply ACLs for OCSP
    setfacl -Rm g:ocsp:rx /etc/swanctl/crls /etc/swanctl/ocsp /opt/pki/x509 /etc/swanctl/x509ca || log "Failed to set ACL for OCSP on necessary directories"
    setfacl -m g:ocsp:r /opt/pki/x509/ca.pem /opt/pki/private/ocsp-key.pem /opt/pki/x509/ocsp.pem /etc/swanctl/crls/index.txt /opt/pki/x509/server.pem || log "Failed to set ACL for OCSP on key and certificate files"

#Validate and recreate symlinks if necessary
    log "Validating and fixing symlinks..."
    declare -A symlinks=(
        ["/etc/swanctl/ocsp/crl.pem"]="/etc/swanctl/crls/crl.pem"
        ["/etc/swanctl/ocsp/ocsp-key.pem"]="/opt/pki/private/ocsp-key.pem"
        ["/etc/swanctl/ocsp/ocsp.pem"]="/opt/pki/x509/ocsp.pem"
        ["/etc/swanctl/x509ocsp/ocsp.pem"]="/opt/pki/x509/ocsp.pem"
        ["/etc/swanctl/private/server-key.pem"]="/opt/pki/private/server-key.pem"
        ["/etc/swanctl/x509/server.pem"]="/opt/pki/x509/server.pem"
        ["/etc/swanctl/x509ca/ca.pem"]="/opt/pki/x509/ca.pem"
        ["/etc/swanctl/x509crl/crl.pem"]="/etc/swanctl/crls/crl.pem"
        ["/etc/nginx/crl/ca.crl"]="/etc/swanctl/crls/ca.crl"
        ["/etc/nginx/crl/crl.pem"]="/etc/swanctl/crls/crl.pem"
        ["/etc/swanctl/ocsp/index.txt"]="/etc/swanctl/crls/index.txt"
        ["/etc/swanctl/ocsp/index.txt.attr"]="/etc/swanctl/crls/index.txt.attr"
        ["/etc/swanctl/crls/ca.srl"]="/opt/pki/x509/ca.srl"

    )

    for link in "${!symlinks[@]}"; do
        target="${symlinks[$link]}"
        if [[ -e "$target" ]]; then
            mkdir -p "$(dirname "$link")" || log "Failed to create parent directory for $link"
            if [[ -L "$link" && "$(readlink "$link")" == "$target" ]]; then
                log "Symlink $link -> $target is valid."
            else
                ln -sf "$target" "$link" && log "Fixed symlink: $link -> $target" || log "Failed to fix symlink: $link -> $target"
            fi
        else
            log "Target $target does not exist. Skipping symlink $link."
        fi
    done

#File-specific ACLs
    local files_to_acl=(
        "/etc/swanctl/private/server-key.pem"
        "/etc/swanctl/x509/server.pem"
        "/etc/swanctl/x509ca/ca.pem"
        "/etc/swanctl/x509crl/crl.pem"
        "/etc/swanctl/x509ocsp/ocsp.pem"
        "/etc/swanctl/ocsp/ocsp.pem"
        "/etc/swanctl/ocsp/ocsp-key.pem"
        "/etc/swanctl/crls/ca.crl"
        "/etc/swanctl/crls/index.txt"
        "/etc/swanctl/crls/index.txt.attr"
        "/etc/swanctl/crls/crl.pem"
    )

    for file in "${files_to_acl[@]}"; do
        if [[ -f "$file" ]]; then
            case "$file" in
                *server-key.pem)
                    setfacl -m g:strongswan:r "$file" || log "Failed to set ACL for $file"
                    ;;
                *ocsp-key.pem | *ocsp.pem  | *server.pem | *ca.pem | *crl.pem)
                    setfacl -m g:strongswan:r "$file" || log "Failed to set ACL for $file"
                    setfacl -m g:ocsp:r "$file" || log "Failed to set ACL for $file"
                    ;;
                *index.txt.attr | *index.txt | *ca.crl)
                    setfacl -m g:ocsp:r "$file" || log "Failed to set ACL for $file"
                    ;;
                *ca.pem | *ocsp.pem | *ca.crl | *crl.pem)
                    setfacl -m g:nginx:r "$file" || log "Failed to set ACL for $file"
                    ;;
            esac
        else
            log "File $file does not exist yet, skipping ACL application."
        fi
    done

#Handle /opt/pki permissions
    setfacl -Rm g:ocsp:rx /opt/pki/private || log "Failed to set ACL for OCSP on /opt/pki/private"
    setfacl -m g:ocsp:r /opt/pki/private/ca-key.pem || log "Failed to set ACL for /opt/pki/private/ca-key.pem"
    setfacl -Rm g:strongswan:rx /opt/pki/x509 || log "Failed to set ACL for StrongSwan on /opt/pki/x509"
    setfacl -Rm g:ocsp:r /opt/pki/x509/ocsp.pem || log "Failed to set ACL for OCSP on /opt/pki/x509/ocsp.pem"

#Exclude unnecessary access
    find /opt/pki/private -type f ! -name "ca-key.pem" -exec setfacl -x g:ocsp {} \;
    find /opt/pki/x509 -type f ! -name "ca.pem" ! -name "server.pem" ! -name "ocsp.pem" \
        -exec setfacl -x g:strongswan -x g:ocsp {} \;

    log "Permissions, ACLs, and symlinks validation completed successfully for /opt/pki and /etc/swanctl!"
}




generate_ca() {
    log "Generating self-signed CA certificate..."

    load_config
    print_variables

#Validate necessary variables
    if [[ -z "$COUNTRY" || -z "$STATE" || -z "$CITY" || -z "$ORGANIZATION" || -z "$ORG_UNIT" || -z "$CA_DURATION" || -z "$CA_NAME" ]]; then
        error_exit "Required variables are not set in the configuration file. Aborting CA generation."
    fi

#Generate a strong random serial number
    log "Generating a strong random serial number..."
    local SERIAL_NUMBER
    SERIAL_NUMBER=$(openssl rand -hex 16) || error_exit "Failed to generate random serial number."
    log "Generated Serial Number: $SERIAL_NUMBER"

#Generate CA private key
    if [[ ! -f "$CA_KEY" ]]; then
        log "Generating CA private key..."
        pki --gen --type rsa --size 4096 --outform pem > "$CA_KEY" || error_exit "Failed to generate CA private key."
        chmod 600 "$CA_KEY"
        chown root:root "$CA_KEY"
    else
        log "CA private key already exists at $CA_KEY."
    fi

#Generate self-signed CA certificate
    if [[ ! -f "$CA_CERT" ]]; then
        log "Generating self-signed CA certificate..."
        pki --self --ca --lifetime "$CA_DURATION" \
            --in "$CA_KEY" \
            --dn "C=$COUNTRY, ST=$STATE, L=$CITY, O=$ORGANIZATION, OU=$ORG_UNIT, CN=$CA_NAME" \
            --serial "$SERIAL_NUMBER" \
            --flag ca \
            --flag keyCertSign \
            --flag crlSign \
            --ocsp "http://$PUBLIC_IP/ocsp" \
            --outform pem > "$CA_CERT" || error_exit "Failed to generate CA certificate."

        chmod 644 "$CA_CERT"
        log "Generated CA certificate at $CA_CERT."
    fi
    log "Creating symlink for CA certificate in swanctl directory..."
#Add CA certificate to index.txt
    log "Adding CA certificate to index.txt..."
    update_crl "add" "$CA_CERT" || error_exit "Failed to add CA certificate to CRL index."
    update_crl "full"
    set_permissions
    log "Self-signed CA certificate generation completed successfully."
}


generate_server() {
    log "Generating server certificate for public IP: $PUBLIC_IP..."

    load_config
    print_variables

    local SERVER_KEY_FILE="$PRIVATE_DIR/server-key.pem"
    local SERVER_CSR_FILE="$TEMP_CERT_DIR/server.csr.pem"
    local SERVER_CERT_FILE="$CERT_DIR/server.pem"

#Generate server private key
    if [[ ! -f "$SERVER_KEY_FILE" ]]; then
        log "Generating server private key..."
        pki --gen --type rsa --size 4096 --outform pem > "$SERVER_KEY_FILE" || error_exit "Failed to generate server private key."
        chmod 600 "$SERVER_KEY_FILE"
        chown root:root "$SERVER_KEY_FILE"
    else
        log "Server private key already exists at $SERVER_KEY_FILE."
    fi

#Generate server CSR
    log "Generating server CSR..."
    pki --req --type priv --in "$SERVER_KEY_FILE" \
        --dn "C=$COUNTRY, ST=$STATE, L=$CITY, O=$ORGANIZATION, OU=$ORG_UNIT, CN=$PUBLIC_IP" \
        --san "IP:$PUBLIC_IP" \
        --outform pem > "$SERVER_CSR_FILE" || error_exit "Failed to generate server CSR."

#Generate a strong random serial number
    local SERIAL_NUMBER
    SERIAL_NUMBER=$(openssl rand -hex 16) || error_exit "Failed to generate random serial number for server certificate."
    log "Generated Serial Number: $SERIAL_NUMBER"

#Issue server certificate
    log "Issuing server certificate..."
    pki --issue --cacert "$CA_CERT" --cakey "$CA_KEY" \
        --type pkcs10 --in "$SERVER_CSR_FILE" \
        --dn "C=$COUNTRY, ST=$STATE, L=$CITY, O=$ORGANIZATION, OU=$ORG_UNIT, CN=$PUBLIC_IP" \
        --crl "http://$PUBLIC_IP/crl/crl.pem" \
        --ocsp "http://$PUBLIC_IP/ocsp" \
        --lifetime "$VPN_DURATION" \
        --flag ipsecTunnel \
        --flag digitalSignature \
        --flag keyEncipherment \
        --flag keyAgreement \
        --flag serverAuth \
        --serial "$SERIAL_NUMBER" \
        --san "$PUBLIC_IP" \
        --outform pem > "$SERVER_CERT_FILE" || error_exit "Failed to issue server certificate."



    chmod 644 "$SERVER_CERT_FILE"
    log "Generated server certificate at $SERVER_CERT_FILE."

#Symlink server certificate for StrongSwan

    log "Adding server certificate to CRL index..."
    update_crl "add" "$SERVER_CERT_FILE" || error_exit "Failed to update CRL index with server certificate."
 
#Clean up
    rm -f "$SERVER_CSR_FILE"
    set_permissions
    log "Server certificate generated successfully."
}

generate_ocsp_cert() {
    log "Generating OCSP responder certificate..."

    load_config
    print_variables

#Ensure CA key, certificate, and CRL infrastructure exist
    if [[ ! -f "$CA_KEY" || ! -f "$CA_CERT" ]]; then
        error_exit "CA key ($CA_KEY) or certificate ($CA_CERT) not found. Ensure CA is initialized before generating OCSP responder certificate."
    fi

    if [[ ! -f "$CRL_DIR/index.txt" ]]; then
        error_exit "CRL index.txt file not found. Ensure CRL infrastructure is initialized."
    fi

#Define file paths
    local OCSP_CSR_FILE="$TEMP_CERT_DIR/ocsp.csr.pem"
    local OCSP_CERT_FILE="$CERT_DIR/ocsp.pem"
    local OCSP_KEY_FILE="$PRIVATE_DIR/ocsp-key.pem"

#Generate OCSP private key
    if [[ ! -f "$OCSP_KEY_FILE" ]]; then
        log "Generating OCSP private key..."
        pki --gen --type rsa --size 4096 --outform pem > "$OCSP_KEY_FILE" || error_exit "Failed to generate OCSP private key."
        chmod 600 "$OCSP_KEY_FILE"
        chown root:root "$OCSP_KEY_FILE"
        log "Generated OCSP private key at $OCSP_KEY_FILE."
    else
        log "OCSP private key already exists at $OCSP_KEY_FILE."
    fi
    log "Creating OpenSSL configuration file for AIA extension..."
cat <<EOF > openssl_ocsp.cnf
[ v3_ocsp ]
keyUsage = critical, digitalSignature
extendedKeyUsage = critical, OCSPSigning
authorityInfoAccess = OCSP;URI:http://$PUBLIC_IP/ocsp
EOF

    log "Created OpenSSL configuration file at openssl_ocsp.cnf."

#Generate OCSP CSR
    log "Generating OCSP CSR..."
    pki --req --type priv --in "$OCSP_KEY_FILE" \
        --dn "C=$COUNTRY, ST=$STATE, L=$CITY, O=$ORGANIZATION, OU=OCSP Responder, CN=$PUBLIC_IP" \
        --san "$PUBLIC_IP" \
        --outform pem > "$OCSP_CSR_FILE" || error_exit "Failed to generate OCSP CSR."
    chmod 644 "$OCSP_CSR_FILE"
    log "Generated OCSP CSR at $OCSP_CSR_FILE."

#Generate a strong random serial number for the OCSP certificate
    log "Generating a strong random serial number for the OCSP certificate..."
    local SERIAL_NUMBER
    SERIAL_NUMBER=$(openssl rand -hex 16) || error_exit "Failed to generate random serial number."
    log "Generated Serial Number: $SERIAL_NUMBER"

#Issue OCSP certificate
    log "Issuing OCSP certificate..."
    log "Signing OCSP certificate with OpenSSL..."
       openssl x509 -req -in "$OCSP_CSR_FILE" \
                    -CA "$CA_CERT" -CAkey "$CA_KEY" -CAcreateserial \
                    -days "$VPN_DURATION" \
                    -extfile openssl_ocsp.cnf -extensions v3_ocsp \
                    -out "$OCSP_CERT_FILE" || error_exit "Failed to issue OCSP certificate with AIA."
    chmod 644 "$OCSP_CERT_FILE"
    log "OCSP certificate issued with AIA extension at $OCSP_CERT_FILE."

    chmod 644 "$OCSP_CERT_FILE"
    log "OCSP certificate issued at $OCSP_CERT_FILE."

#Create symlink for OCSP certificate in swanctl directory
    mkdir -p /etc/swanctl/ocsp
#Add OCSP certificate to CRL index
    log "Adding OCSP certificate to CRL index..."
    openssl x509 -in "$OCSP_CERT_FILE" -noout || error_exit "Invalid OCSP certificate: $OCSP_CERT_FILE"
    update_crl "add" "$OCSP_CERT_FILE" || error_exit "Failed to update CRL index with OCSP certificate."
    update_crl "full"
    set_permissions

#Clean up
    rm -f "$OCSP_CSR_FILE"
    log "OCSP responder certificate generated successfully."
}


revoke_client() {
    local client_identifier="$1"  # Could be client name or cert path
    local reason="${2:-superseded}"  # Optional, defaults to 'superseded'

    log "Revoking client certificate for: $client_identifier..."
    
#Assume certificate path based on client name
    local cert_file
    if [[ "$client_identifier" =~ ^/ ]]; then
    #If input starts with '/', assume it's a full path
        cert_file="$client_identifier"
    else
    #Assume it's a client name and construct the default path
        cert_file="/opt/pki/x509/${client_identifier}.pem"
    fi

#Check if the certificate file exists
    if [[ ! -f "$cert_file" ]]; then
        log "Certificate file not found at default path: $cert_file"
        read -p "Please provide the full path to the certificate file for $client_identifier: " cert_file
        if [[ ! -f "$cert_file" ]]; then
            error_exit "Certificate file not found: $cert_file. Aborting revocation."
        fi
    fi

#Prompt for revocation reason if not provided
    if [[ -z "$2" ]]; then
        echo "Please provide the revocation reason (default: superseded):"
        echo "1) superseded"
        echo "2) keyCompromise"
        echo "3) affiliationChanged"
        echo "4) cessationOfOperation"
        echo "5) certificateHold"
        read -p "Enter the number corresponding to the reason: " reason_choice
        case "$reason_choice" in
            1) reason="superseded" ;;
            2) reason="keyCompromise" ;;
            3) reason="affiliationChanged" ;;
            4) reason="cessationOfOperation" ;;
            5) reason="certificateHold" ;;
            *) reason="superseded" ;;
        esac
    fi

    update_crl "revoke" "$cert_file" "$reason" || error_exit "Failed to revoke client certificate."
    update_crl "full"
    log "Client certificate revoked successfully."
}



normalize_serials() {
    local index_file="$CRL_DIR/index.txt"

    log "Normalizing serial numbers in $index_file to lowercase..."
    sed -i -E 's/([0-9A-F]{32})/\L\1/g' "$index_file" || error_exit "Failed to normalize serial numbers in $index_file."
    log "Serial numbers normalized successfully."
}


generate_client() {
    local email=$(echo "$1" | xargs)
    local duration_months=${2:-12}  # Default to 12 months if not provided
    local duration_days=$((duration_months * 30))
    log "Generating client certificate for: $email..."

    load_config
    print_variables

    local CLIENT_KEY_FILE="$PRIVATE_DIR/${email}-key.pem"
    local CLIENT_CERT_FILE="$CERT_DIR/${email}.pem"
    local CLIENT_CSR_FILE="$TEMP_CERT_DIR/${email}.csr.pem"

#Check if certificate already exists
    if [[ -f "$CLIENT_CERT_FILE" ]]; then
        log "Certificate already exists for client: $email. Skipping generation."
        return
    fi

#Generate private key
    if [[ ! -f "$CLIENT_KEY_FILE" ]]; then
        log "Generating client private key..."
        pki --gen --type rsa --size 4096 --outform pem > "$CLIENT_KEY_FILE" || \
            error_exit "Failed to generate client private key."
        chmod 600 "$CLIENT_KEY_FILE"
    else
        log "Private key already exists for client: $email."
    fi

#Generate CSR
    log "Generating client CSR..."
    pki --req --type priv --in "$CLIENT_KEY_FILE" \
        --dn "C=$COUNTRY, ST=$STATE, L=$CITY, O=$ORGANIZATION, OU=$ORG_UNIT, CN=$email" \
        --san "email:$email" \
        --outform pem > "$CLIENT_CSR_FILE" || error_exit "Failed to generate client CSR."

#Generate a unique serial number for the certificate
    log "Generating a unique serial number for the client certificate..."
    local SERIAL_NUMBER
    SERIAL_NUMBER=$(openssl rand -hex 16) || error_exit "Failed to generate random serial number."
    log "Generated Serial Number: $SERIAL_NUMBER"

#Issue certificate
    log "Issuing client certificate..."
    pki --issue --cacert "$CA_CERT" --cakey "$CA_KEY" \
        --type pkcs10 --in "$CLIENT_CSR_FILE" \
        --dn "C=$COUNTRY, ST=$STATE, L=$CITY, O=$ORGANIZATION, OU=$ORG_UNIT, CN=$email" \
        --crl "http://$PUBLIC_IP/crl/crl.pem" \
        --ocsp "http://$PUBLIC_IP/ocsp" \
        --lifetime "$duration_days" \
        --flag digitalSignature \
        --flag keyAgreement \
        --flag clientAuth \
        --flag ipsecClient \
        --serial "$SERIAL_NUMBER" \
        --san "$email" \
        --outform pem > "$CLIENT_CERT_FILE" || error_exit "Failed to issue client certificate."

    chmod 644 "$CLIENT_CERT_FILE"
    log "Client certificate generated at $CLIENT_CERT_FILE."

#Add certificate entry to index.txt via update_crl
    log "Adding client certificate to index.txt..."
    update_crl "add" "$CLIENT_CERT_FILE"  || error_exit "Failed to add client certificate to index.txt."

#Export bundle (if applicable)
    export_bundle "$email"

#Clean up CSR
    log "Cleaning up CSR..."
    rm -f "$CLIENT_CSR_FILE"

    log "Client certificate generation completed for $email."
}




generate_powershell_script() {
    local client_id="$1"
    local powershell_script="/opt/pki/${client_id}_vpn_setup.ps1"


    rm -f "$powershell_script"

    cat <<EOF > "$powershell_script"
# PowerShell VPN Setup Script
\$vpnName = "${DNS_NAME}"
\$serverIP = "${PUBLIC_IP}"
\$dnsSuffix = "${DNS_NAME}"
\$route = "${ROUTE_SUBNETS}" # Modify with your specific route

function Remove-VpnConnectionIfExists {
    try {
        \$existingVpn = Get-VpnConnection -Name \$vpnName -ErrorAction Stop
        if (\$existingVpn) {
            Write-Host "A VPN connection with the name '\$vpnName' already exists. Removing it..."
            Remove-VpnConnection -Name \$vpnName -Force -ErrorAction Stop
        }
    } catch {
        Write-Host "No existing VPN connection found with the name '\$vpnName'. Proceeding to add new connection."
    }
}

Remove-VpnConnectionIfExists

try {
    Add-VpnConnection -Name "\$vpnName" -ServerAddress \$serverIP -TunnelType IKEv2 -AuthenticationMethod MachineCertificate -EncryptionLevel Maximum -ErrorAction Stop
    Set-VpnConnection -Name "\$vpnName" -DnsSuffix \$dnsSuffix
    Set-VpnConnection -Name "\$vpnName" -SplitTunneling \$True
    Add-VpnConnectionRoute -ConnectionName "\$vpnName" -DestinationPrefix \$route
   
    Set-VpnConnectionIPsecConfiguration -ConnectionName "\$vpnname" \`
        -AuthenticationTransformConstants GCMAES256 \`
        -CipherTransformConstants GCMAES256 \`
        -EncryptionMethod AES256 \`
        -IntegrityCheckMethod SHA256 \`
        -DHGroup ECP256 \`
        -PfsGroup ECP256 \`
        -PassThru -Force 


    Write-Host "VPN profile '\$vpnName' created successfully. It will prompt for username and password."

    \$vpnProfile = Get-VpnConnection -Name \$vpnName
    Write-Host "VPN Profile Details:"
    \$vpnProfile | Format-List
} catch {
    Write-Host "Failed to configure the VPN profile: \$_. Exception message."
    Exit 1
}
EOF

#Log script creation
    echo "PowerShell script generated at $powershell_script"
}

export_bundle() {

    local client_id=$(echo "$1" | xargs)

    log "Exporting certificates and configuration for client ID: $client_id..."

    load_config
    print_variables

    local key_path="$PRIVATE_DIR/${client_id}-key.pem"
    local cert_path="$CERT_DIR/${client_id}.pem"
    local ca_path="$CA_DIR/ca.pem"
    local sswan_file="/opt/pki/${DNS_NAME}_${client_id}.sswan"
    local ps1_script="/opt/pki/${client_id}_vpn_setup.ps1"
   

    if [[ ! -f "$key_path" ]]; then
        error_exit "Client private key file not found: $key_path"
    fi
    if [[ ! -f "$cert_path" ]]; then
        error_exit "Client certificate file not found: $cert_path"
    fi
    if [[ ! -f "$ca_path" ]]; then
        error_exit "CA certificate file not found: $ca_path"
    fi

    openssl pkcs12 -export -out "/opt/pki/${client_id}.p12" \
        -inkey "$key_path" \
        -in "$cert_path" \
        -certfile "$ca_path" \
        -caname "$VPN_CA" \
        -password pass:"$PFX_PASSWORD" 2>/dev/null || error_exit "Failed to create PKCS#12 bundle"

    generate_sswan_file "$client_id" "$cert_path" "$key_path" "$ca_path"

    generate_mobileconfig "$client_id"

 
    generate_powershell_script "$client_id"

    tar -czvf "/opt/pki/${client_id}_bundle.tar.gz" \
        -C /opt/pki "${client_id}.p12" "$(basename "$sswan_file")" \
        -C /opt/pki "${client_id}.mobileconfig" \
        -C "$CA_DIR" ca.pem \
        -C /opt/pki "${client_id}_vpn_setup.ps1" \
        -C "$PRIVATE_DIR" "${client_id}-key.pem" \
        -C "$CERT_DIR" "${client_id}.pem" || error_exit "Failed to create tarball"
        
    rm -f "/opt/pki/${client_id}.p12" "$sswan_file" "/opt/pki/${client_id}.mobileconfig" "$ps1_script" "$exe_file"

    log "Bundle created successfully at /opt/pki/${client_id}_bundle.tar.gz"
}

generate_custom_server() {
    log "Generating custom server certificate for DNS_NAME=$DNS_NAME..."

    load_config
    print_variables

#Paths for server key, CSR, and certificate
    local SERVER_KEY_FILE="/opt/pki/private/${DNS_NAME}.server-key.pem"
    local SERVER_CSR_FILE="$TEMP_CERT_DIR/${DNS_NAME}.server.csr.pem"
    local SERVER_CERT_FILE="/opt/pki/x509/${DNS_NAME}.server.pem"
    local SWANCTL_KEY_SYMLINK="/etc/swanctl/private/${DNS_NAME}.server-key.pem"
    local SWANCTL_CERT_SYMLINK="/etc/swanctl/x509/${DNS_NAME}.server.pem"
    local OUTPUT_DIR="/root"
    local P12_FILE="${OUTPUT_DIR}/${DNS_NAME}.p12"
    local TAR_FILE="${OUTPUT_DIR}/${DNS_NAME}_certs.tar.gz"

    if [[ -z "$DNS_NAME" ]]; then
        error_exit "DNS_NAME is not set. Aborting certificate generation."
    fi

#Ensure required directories exist
    mkdir -p "/opt/pki/private" "/opt/pki/x509" "/etc/swanctl/private" "/etc/swanctl/x509" "$TEMP_CERT_DIR"

#Generate private key
    if [[ ! -f "$SERVER_KEY_FILE" ]]; then
        log "Generating server private key in /opt/pki/private..."
        pki --gen --type rsa --size 4096 --outform pem > "$SERVER_KEY_FILE" || error_exit "Failed to generate server private key."
        chmod 600 "$SERVER_KEY_FILE"
        chown root:root "$SERVER_KEY_FILE"
    else
        log "Server private key already exists at $SERVER_KEY_FILE."
    fi

#Symlink private key to swanctl directory
    log "Creating symlink for server private key in /etc/swanctl/private..."
    ln -sf "$SERVER_KEY_FILE" "$SWANCTL_KEY_SYMLINK" || error_exit "Failed to create symlink for server private key."
    chmod 640 "$SWANCTL_KEY_SYMLINK"

#Generate CSR
    if [[ ! -f "$SERVER_CSR_FILE" ]]; then
        log "Generating server CSR..."
        pki --req --type priv --in "$SERVER_KEY_FILE" \
            --dn "C=$COUNTRY, ST=$STATE, L=$CITY, O=$ORGANIZATION, OU=$ORG_UNIT, CN=$DNS_NAME" \
            --san "DNS:$DNS_NAME" \
            --outform pem > "$SERVER_CSR_FILE" || error_exit "Failed to generate server CSR."
    else
        log "Server CSR already exists at $SERVER_CSR_FILE."
    fi

#Generate serial number and issue certificate
    local SERIAL_NUMBER
    SERIAL_NUMBER=$(openssl rand -hex 16) || error_exit "Failed to generate random serial number."
    log "Generated Serial Number: $SERIAL_NUMBER"

    if [[ ! -f "$SERVER_CERT_FILE" ]]; then
        log "Issuing server certificate..."
        pki --issue --cacert "$CA_CERT" --cakey "$CA_KEY" \
            --type pkcs10 --in "$SERVER_CSR_FILE" \
            --dn "C=$COUNTRY, ST=$STATE, L=$CITY, O=$ORGANIZATION, OU=$ORG_UNIT, CN=$DNS_NAME" \
            --crl "http://$PUBLIC_IP/crl/crl.pem" \
            --ocsp "http://$PUBLIC_IP/ocsp" \
            --san "DNS:$DNS_NAME" \
            --lifetime "$VPN_DURATION" \
            --flag ipsecTunnel \
            --flag serverAuth \
            --serial "$SERIAL_NUMBER" \
            --outform pem > "$SERVER_CERT_FILE" || error_exit "Failed to issue server certificate."
        chmod 644 "$SERVER_CERT_FILE"
        chown root:root "$SERVER_CERT_FILE"
    else
        log "Server certificate already exists at $SERVER_CERT_FILE."
    fi

#Symlink certificate to swanctl directory
    log "Creating symlink for server certificate in /etc/swanctl/x509..."
    ln -sf "$SERVER_CERT_FILE" "$SWANCTL_CERT_SYMLINK" || error_exit "Failed to create symlink for server certificate."
    chmod 644 "$SWANCTL_CERT_SYMLINK"

#Export and package PKCS#12
    log "Exporting certificate and key to PKCS#12 format..."
    openssl pkcs12 -export \
        -out "$P12_FILE" \
        -inkey "$SERVER_KEY_FILE" \
        -in "$SERVER_CERT_FILE" \
        -certfile "$CA_CERT" \
        -name "$DNS_NAME Server Cert" \
        -passout pass:"$PFX_PASSWORD" || error_exit "Failed to export certificate to PKCS#12 format."

    tar -czf "$TAR_FILE" -C "$OUTPUT_DIR" "$(basename "$P12_FILE")" || error_exit "Failed to create tar.gz archive."
    rm -f "$P12_FILE"

#Add certificate to index.txt
    log "Adding server certificate to index.txt..."
    update_crl add "$SERVER_CERT_FILE" || error_exit "Failed to add server certificate to index.txt."
    set_permissions
    log "Custom server certificate for $DNS_NAME generated, exported, and packaged successfully to $TAR_FILE."
    return 0
}


generate_sswan_file() {
    local client_name="$1"
    local client_cert_file="$2"
    local client_key_file="$3"
    local ca_cert_file="$4"

    log "Generating .sswan file for $client_name..."

    local UUID
    UUID=$(uuidgen)

    if [[ -z "$DNS_NAME" || -z "$PUBLIC_IP" ]]; then
        echo "Error: DNS_NAME and PUBLIC_IP must be set."
        exit 1
    fi

    local VPN_NAME="$DNS_NAME"

 
    local SSWAN_FILE="/opt/pki/${DNS_NAME}_${client_name}.sswan"

    mkdir -p /opt/pki

    local CA_CERT_B64
    local CLIENT_CERT_B64
    local CLIENT_KEY_B64

    CA_CERT_B64=$(base64 -w 0 "$ca_cert_file")
    CLIENT_CERT_B64=$(base64 -w 0 "$client_cert_file")
    CLIENT_KEY_B64=$(base64 -w 0 "$client_key_file")

#check if base64 encoding was successful
    if [[ -z "$CA_CERT_B64" || -z "$CLIENT_CERT_B64" || -z "$CLIENT_KEY_B64" ]]; then
        echo "Error: Failed to base64-encode one or more certificate/key files."
        exit 1
    fi

#Create the .sswan JSON file with encoded data
    bash -c "cat > '$SSWAN_FILE'" <<SWEOF
{
    "uuid": "$UUID",
    "name": "$VPN_NAME",
    "type": "ikev2-cert",
    "remote": {
        "addr": "$PUBLIC_IP",
        "auth": "pubkey",
        "ca_cert": {
            "data": "$CA_CERT_B64",
            "format": "X509"
        }
    },
    "local": {
        "auth": "pubkey",
        "cert": {
            "data": "$CLIENT_CERT_B64",
            "format": "X509"
        },
        "key": {
            "data": "$CLIENT_KEY_B64",
            "format": "PKCS8"
        }
    },
    "ike": {
        "proposals": [
            "aes256gcm16-sha256-ecp256, aes256-sha384-ecp521, aes256-sha384-modp2048"                   
        ]
    },
    "esp": {
        "proposals": [
            " aes256gcm16-ecp256, aes256gcm16, aes256-sha384, aes256gcm128-sha256-ecp256, aes128gcm128-sha384-ecp384"
        ]
    }
}
SWEOF

#Set ownership and permissions
    chown root:root "$SSWAN_FILE"
    chmod 600 "$SSWAN_FILE"

    log ".sswan file generated at $SSWAN_FILE"
}



init_openssl_config() {
    log "Initializing OpenSSL configuration..."

#Load configuration variables
    load_config
    print_variables

#Define the OpenSSL configuration file path
    local openssl_conf="/etc/ssl/openssl.cnf"

#Backup existing OpenSSL configuration if it exists
    if [[ -f "$openssl_conf" ]]; then
        cp "$openssl_conf" "${openssl_conf}.bak" || error_exit "Failed to backup existing OpenSSL configuration."
    fi

#Generate a new OpenSSL configuration file
    cat > "$openssl_conf" <<EOF
[ ca ]
default_ca = CA_default

[ CA_default ]
dir               = $CRL_DIR
certs             = $CERT_DIR
crl_dir           = $CRL_DIR
new_certs_dir     = $CERT_DIR
database          = $CRL_DIR/index.txt
serial            = $SRL_FILE
crlnumber         = $CRL_DIR/crlnumber
certificate       = $CA_CERT
private_key       = $CA_KEY
RANDFILE          = \$dir/private/.rand

default_days      = $VPN_DURATION
default_crl_days  = $CRL_DURATION
default_md        = sha256
preserve          = no
policy            = policy_any

[ policy_any ]
countryName             = optional
stateOrProvinceName     = optional
localityName            = optional
organizationName        = optional
organizationalUnitName  = optional
commonName              = supplied
emailAddress            = optional

[ req ]
default_bits       = 4096
default_keyfile    = privkey.pem
default_md         = sha256
prompt             = no
distinguished_name = req_distinguished_name
x509_extensions    = v3_ca

[ req_distinguished_name ]
C                  = $COUNTRY
ST                 = $STATE
L                  = $CITY
O                  = $ORGANIZATION
OU                 = $ORG_UNIT
CN                 = $CA_NAME

[ v3_ca ]
subjectKeyIdentifier   = hash
authorityKeyIdentifier = keyid:always,issuer:always
basicConstraints       = critical,CA:true
keyUsage               = critical,cRLSign,keyCertSign

[ v3_ocsp ]
authorityKeyIdentifier = keyid:always,issuer:always
basicConstraints       = CA:FALSE
keyUsage               = critical,digitalSignature
extendedKeyUsage       = critical,OCSPSigning

[ ocsp ]
default_responder  = http://$PUBLIC_IP/ocsp
OCSPResponderCert  = $OCSP_CERT
OCSPResponderKey   = $OCSP_KEY
EOF

#Set ownership and permissions
    chmod 644 "$openssl_conf"
    chown root:root "$openssl_conf"

    log "OpenSSL configuration initialized successfully at $openssl_conf."
}


generate_mobileconfig() {
    log "Generating mobileconfig for VPN configuration..."
    load_config

    local client_name="$1"
    local export_dir="/opt/pki/"
    local p12_password="$PFX_PASSWORD"
    local p12_file_enc="$export_dir$client_name.p12"

#Load variables from strongconn.conf
    CONFIG_PATH="/etc/strongconn.conf"
    source "$CONFIG_PATH"


    local server_addr="$PUBLIC_IP"


    p12_base64=$(base64 -w 0 "$p12_file_enc")
    [ -z "$p12_base64" ] && error_exit "Could not encode .p12 file."


    local ca_cert_file="$CA_DIR/ca.pem"
    ca_base64=$(base64 -w 0 "$ca_cert_file")
    [ -z "$ca_base64" ] && error_exit "Could not encode CA certificate."

    local uuid_vpn_payload=$(uuidgen)
    local uuid_pkcs12=$(uuidgen)
    local uuid_ca=$(uuidgen)
    local uuid_main=$(uuidgen)

    while [[ "$uuid_vpn_payload" == "$uuid_pkcs12" || "$uuid_vpn_payload" == "$uuid_ca" || "$uuid_vpn_payload" == "$uuid_main" || "$uuid_pkcs12" == "$uuid_ca" || "$uuid_pkcs12" == "$uuid_main" || "$uuid_ca" == "$uuid_main" ]]; do
        uuid_vpn_payload=$(uuidgen)
        uuid_pkcs12=$(uuidgen)
        uuid_ca=$(uuidgen)
        uuid_main=$(uuidgen)
    done

#Create mobileconfig file
    local mc_file="$export_dir$client_name.mobileconfig"
    cat > "$mc_file" <<EOF
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
  <key>PayloadContent</key>
  <array>
    <dict>
      <key>IKEv2</key>
      <dict>
        <key>AuthenticationMethod</key>
        <string>Certificate</string>
        <key>ChildSecurityAssociationParameters</key>
        <dict>
          <key>DiffieHellmanGroup</key>
          <integer>19</integer>
          <key>EncryptionAlgorithm</key>
          <string>AES-256-GCM</string>
          <key>LifeTimeInMinutes</key>
          <integer>1410</integer>
        </dict>
        <key>DeadPeerDetectionRate</key>
        <string>Medium</string>
        <key>DisableRedirect</key>
        <true/>
        <key>EnableCertificateRevocationCheck</key>
        <integer>0</integer>
        <key>EnablePFS</key>
        <integer>0</integer>
        <key>IKESecurityAssociationParameters</key>
        <dict>
          <key>DiffieHellmanGroup</key>
          <integer>19</integer>
          <key>EncryptionAlgorithm</key>
          <string>AES-256-GCM</string>
          <key>IntegrityAlgorithm</key>
          <string>SHA2-256</string>
          <key>LifeTimeInMinutes</key>
          <integer>1410</integer>
        </dict>
        <key>LocalIdentifier</key>
        <string>$client_name</string>
        <key>PayloadCertificateUUID</key>
        <string>$uuid_pkcs12</string>
        <key>OnDemandEnabled</key>
        <integer>0</integer>
        <key>OnDemandRules</key>
        <array>
          <dict>
            <key>InterfaceTypeMatch</key>
            <string>WiFi</string>
            <key>URLStringProbe</key>
            <string>http://captive.apple.com/hotspot-detect.html</string>
            <key>Action</key>
            <string>Connect</string>
          </dict>
          <dict>
            <key>InterfaceTypeMatch</key>
            <string>Cellular</string>
            <key>Action</key>
            <string>Disconnect</string>
          </dict>
          <dict>
            <key>Action</key>
            <string>Ignore</string>
          </dict>
        </array>
        <key>RemoteAddress</key>
        <string>$server_addr</string>
        <key>RemoteIdentifier</key>
        <string>$server_addr</string>
        <key>UseConfigurationAttributeInternalIPSubnet</key>
        <integer>0</integer>
      </dict>
      <key>IPv4</key>
      <dict>
        <key>OverridePrimary</key>
        <integer>1</integer>
      </dict>
      <key>PayloadDescription</key>
      <string>Configures VPN settings</string>
      <key>PayloadDisplayName</key>
      <string>VPN</string>
      <key>PayloadOrganization</key>
      <string>IKEv2 VPN</string>
      <key>PayloadIdentifier</key>
      <string>com.apple.vpn.managed.$uuid_vpn_payload</string>
      <key>PayloadType</key>
      <string>com.apple.vpn.managed</string>
      <key>PayloadUUID</key>
      <string>$uuid_vpn_payload</string>
      <key>PayloadVersion</key>
      <integer>1</integer>
      <key>Proxies</key>
      <dict>
        <key>HTTPEnable</key>
        <integer>0</integer>
        <key>HTTPSEnable</key>
        <integer>0</integer>
      </dict>
      <key>UserDefinedName</key>
      <string>$server_addr</string>
      <key>VPNType</key>
      <string>IKEv2</string>
    </dict>
    <dict>
      <key>Password</key>
      <string>$p12_password</string>
      <key>PayloadCertificateFileName</key>
      <string>$client_name.p12</string>
      <key>PayloadContent</key>
      <data>
$p12_base64
      </data>
      <key>PayloadDescription</key>
      <string>Adds a PKCS#12-formatted certificate</string>
      <key>PayloadDisplayName</key>
      <string>$client_name</string>
      <key>PayloadIdentifier</key>
      <string>com.apple.security.pkcs12.$uuid_pkcs12</string>
      <key>PayloadType</key>
      <string>com.apple.security.pkcs12</string>
      <key>PayloadUUID</key>
      <string>$uuid_pkcs12</string>
      <key>PayloadVersion</key>
      <integer>1</integer>
    </dict>
    <dict>
      <key>PayloadContent</key>
      <data>
$ca_base64
      </data>
      <key>PayloadCertificateFileName</key>
      <string>ikev2vpnca</string>
      <key>PayloadDescription</key>
      <string>Adds a CA root certificate</string>
      <key>PayloadDisplayName</key>
      <string>Certificate Authority (CA)</string>
      <key>PayloadIdentifier</key>
      <string>com.apple.security.root.$uuid_ca</string>
      <key>PayloadType</key>
      <string>com.apple.security.root</string>
      <key>PayloadUUID</key>
      <string>$uuid_ca</string>
      <key>PayloadVersion</key>
      <integer>1</integer>
    </dict>
  </array>
  <key>PayloadDisplayName</key>
  <string>IKEv2 VPN $server_addr</string>
  <key>PayloadIdentifier</key>
  <string>com.apple.vpn.managed.$uuid_main</string>
  <key>PayloadRemovalDisallowed</key>
  <false/>
  <key>PayloadType</key>
  <string>Configuration</string>
  <key>PayloadUUID</key>
  <string>$uuid_main</string>
  <key>PayloadVersion</key>
  <integer>1</integer>
</dict>
</plist>
EOF

    if [ "$export_to_home_dir" = 1 ]; then
        chown "$_USER:$_USER" "$mc_file"
    fi
    chmod 600 "$mc_file"
}

generate_csr() {
    local client_type="$1"  
    shift
    local dns_name="$1"
    shift

    if [[ -z "$client_type" || -z "$dns_name" ]]; then
        error_exit "Usage: generate_csr <internal|third-party> <DNS_NAME>"
    fi

    source /etc/strongconn.conf

    PKI_DIR="/opt/pki"
    PRIVATE_KEY="${PKI_DIR}/${dns_name}.key.pem"
    CSR="${PKI_DIR}/${dns_name}.csr.pem"
    mkdir -p "${PKI_DIR}"
    if [ ! -w "${PKI_DIR}" ]; then
        error_exit "Error: ${PKI_DIR} is not writable. Ensure the user has the correct permissions."
    fi

    if [ ! -f "${PRIVATE_KEY}" ]; then
        log "Generating private key for ${dns_name}..."
        pki --gen --type rsa --size 4096 --outform pem > "${PRIVATE_KEY}" || error_exit "Error generating private key"
        log "Generated private key at ${PRIVATE_KEY}"
    else
        log "Private key already exists at ${PRIVATE_KEY}"
    fi

    CSR_CONFIG="/tmp/${dns_name}_csr.conf"
    cat > "${CSR_CONFIG}" <<CEOF
[ req ]
default_bits       = 4096
default_md         = sha256
prompt             = no
distinguished_name = req_distinguished_name
req_extensions     = v3_req

[ req_distinguished_name ]
C                  = ${COUNTRY}
ST                 = ${STATE}
L                  = ${CITY}
O                  = ${ORGANIZATION}
OU                 = ${ORG_UNIT}
CN                 = ${dns_name}

[ v3_req ]
keyUsage           = critical, digitalSignature, keyEncipherment
extendedKeyUsage   = serverAuth
subjectAltName     = @alt_names
CEOF

    if [ "$client_type" == "internal" ]; then
        cat >> "${CSR_CONFIG}" <<CEOF
authorityInfoAccess = OCSP;URI:http://${PUBLIC_IP}/oscp

[ alt_names ]
DNS.1 = ${dns_name}
IP.1  = ${PUBLIC_IP}
CEOF
    else
    #For third-party CSRs, omit authorityInfoAccess
        cat >> "${CSR_CONFIG}" <<CEOF
[ alt_names ]
DNS.1 = ${dns_name}
IP.1  = ${PUBLIC_IP}
CEOF
    fi

    log "Generating CSR for ${dns_name} as ${client_type}..."
    openssl req -new -key "${PRIVATE_KEY}" -out "${CSR}" -config "${CSR_CONFIG}" || error_exit "Failed to generate CSR"
    log "CSR generated successfully and saved to ${CSR}"

    rm -f "${CSR_CONFIG}"
}

init_db() {
    log "Initializing swanctl directories and preparing OpenSSL environment..."

#Load the configuration file and print variables
    load_config
    print_variables

#Create primary directories with proper permissions
    log "Creating primary directories..."
    mkdir -p "$TEMP_CERT_DIR" "$CERT_DIR" "$PRIVATE_DIR" "$CA_DIR" "$CRL_DIR" "$SRL_DIR" || \
        error_exit "Failed to create required directories."

#Set permissions and ownership for primary directories
    chmod 750 "$PRIVATE_DIR"
    chmod 755 "$TEMP_CERT_DIR" "$CERT_DIR" "$CA_DIR" "$CRL_DIR" "$SRL_DIR"
    chown -R root:root "$TEMP_CERT_DIR" "$CERT_DIR" "$PRIVATE_DIR" "$CA_DIR" "$CRL_DIR" "$SRL_DIR"
    chown -R root:ocsp "$OCSP_DIR"
    sudo chmod 710 /opt/pki/private
    sudo chown root:ocsp /opt/pki/private
#Create additional directories required for StrongSwan
    local additional_dirs=(
        "/etc/swanctl/x509ocsp"
        "/etc/swanctl/x509aa"
        "/etc/swanctl/x509ac"
        "/etc/swanctl/x509crl"
        "/etc/swanctl/pubkey"
        "/etc/swanctl/rsa"
        "/etc/swanctl/ecdsa"
        "/etc/swanctl/bliss"
        "/etc/swanctl/pkcs8"
        "/etc/swanctl/pkcs12"
        "/etc/swanctl/crls"
        "/opt/pki"
        "/opt/pki/private"
        "/opt/pki/x509"
    )
    
    for dir in "${additional_dirs[@]}"; do
        mkdir -p "$dir" || error_exit "Failed to create additional directory: $dir."
    done

#Set permissions for additional directories
    chmod 755 /etc/swanctl/x509* /opt/pki/x509
    chmod 700 /opt/pki/private

#Initialize CRL infrastructure
    log "Initializing CRL database and number files..."
   

#Initialize the OpenSSL configuration
    init_openssl_config
    cat <<EOF > /etc/swanctl/crls/index.txt.attr
unique_subject = no

EOF
    set_permissions

    update_crl init || error_exit "Failed to initialize CRL infrastructure."
   
    log "Initialization completed successfully."
}

list_certs() {
    echo "Listing certificates..."
    load_config
    print_variables

    certs_dir="$CERT_DIR"
    ca_file="$CA_DIR/ca.pem"
    crl_file="$CRL_DIR/crl.pem"

#Verify the CRL file exists
    if [[ ! -f "$crl_file" ]]; then
        error_exit "CRL file not found: $crl_file. Please generate or update the CRL."
    fi

    echo "+-----------------+-----------------+-----------------+-----------------+-----------------+-----------------+-----------------+"
    printf "| %-15s | %-15s | %-15s | %-15s | %-15s | %-15s | %-15s |\n" "Filename" "CName" "Valid From" "Valid To" "EKU" "Status" "Issuer"
    echo "+-----------------+-----------------+-----------------+-----------------+-----------------+-----------------+-----------------+"

#Function to check certificate status against CRL
    check_cert_status() {
        local cert_file="$1"
        local status

    #Verify the certificate against the CRL
        if openssl verify -CAfile "$ca_file" -crl_check -CRLfile "$crl_file" "$cert_file" >/dev/null 2>&1; then
            status="Valid"
        else
            status="Revoked"
        fi

        echo "$status"
    }

    for cert in "$certs_dir"/*.pem; do
        [ -f "$cert" ] || continue

        filename=$(basename "$cert")
        cname=$(openssl x509 -in "$cert" -noout -subject -nameopt multiline | grep 'commonName' | sed 's/.*= //')
        dates=$(openssl x509 -in "$cert" -noout -dates)
        valid_from=$(echo "$dates" | grep 'notBefore' | cut -d'=' -f2 | awk '{print $4"-"$1}')
        valid_to=$(echo "$dates" | grep 'notAfter' | cut -d'=' -f2 | awk '{print $4"-"$1}')
        eku=$(openssl x509 -in "$cert" -noout -ext extendedKeyUsage 2>/dev/null | grep -v 'Extended Key Usage' | tr -d ' ')
        status=$(check_cert_status "$cert")
        issuer=$(openssl x509 -in "$cert" -noout -issuer -nameopt multiline | grep 'commonName' | sed 's/.*= //')

        printf "| %-15s | %-15s | %-15s | %-15s | %-15s | %-15s | %-15s |\n" \
               "${filename:0:15}" \
               "${cname:0:15}" \
               "${valid_from:0:15}" \
               "${valid_to:0:15}" \
               "${eku:0:15}" \
               "$status" \
               "${issuer:0:15}"
    done

    echo "+-----------------+-----------------+-----------------+-----------------+-----------------+-----------------+-----------------+"

}

rebuild_crl() {
    log "Starting CRL rebuild process..."

#Directories to scan
    local scan_dirs=("/etc/swanctl" "/opt/pki")
    local cert_dir="/opt/pki/x509"
    local key_dir="/opt/pki/private"
    local crl_index_file="$CRL_DIR/index.txt"
    local crl_number_file="$CRL_DIR/crlnumber"
    local backup_dir="/opt/pki"
    local timestamp
    timestamp=$(date +"%Y%m%d_%H%M%S")
    local backup_file="$backup_dir/crl_backup_$timestamp.tar.gz"

#-----------------------------------
#Backup Existing CRL Files
#-----------------------------------
    if [[ -f "$crl_index_file" || -f "$crl_number_file" ]]; then
        log "Backing up existing CRL-related files to: $backup_file"
        mkdir -p "$backup_dir"
        tar -czf "$backup_file" -C "$CRL_DIR" index.txt crlnumber ca.crl 2>/dev/null || \
            error_exit "Failed to create backup tarball."
        log "Backup completed successfully."
    fi

#Ensure necessary directories exist
    log "Ensuring necessary directories and files exist..."
    mkdir -p "$CRL_DIR"
    touch "$crl_index_file" "$crl_number_file"
    [[ ! -s "$crl_number_file" ]] && echo "01" > "$crl_number_file"

#Clear existing files
    log "Clearing existing CRL-related files..."
    >"$crl_index_file"
    echo "01" >"$crl_number_file"

#-----------------------------------
#Identify the Active CA
#-----------------------------------
    log "Scanning for active CA certificate and key..."
    local ca_cert=""
    local ca_key=""
    for key_file in "$key_dir"/*.key; do
        local potential_ca_cert="${key_dir}/../x509/$(basename "${key_file%.key}.pem")"
        if [[ -f "$potential_ca_cert" ]]; then
            ca_cert="$potential_ca_cert"
            ca_key="$key_file"
            break
        fi
    done

    if [[ -z "$ca_cert" || -z "$ca_key" ]]; then
        error_exit "No active CA certificate and key pair found!"
    fi
    log "Active CA certificate: $ca_cert"
    log "Active CA key: $ca_key"

#-----------------------------------
#Scan All Certificates
#-----------------------------------
    log "Scanning directories for certificates issued by the active CA..."
    local certs=()
    for dir in "${scan_dirs[@]}"; do
        while IFS= read -r -d '' cert; do
        #Verify if the certificate was issued by the active CA
            if openssl verify -CAfile "$ca_cert" "$cert" > /dev/null 2>&1; then
                log "Valid certificate found: $cert"
                certs+=("$cert")
            else
                log "Ignoring certificate not signed by active CA: $cert"
            fi
        done < <(find "$dir" -type f -name "*.pem" -print0)
    done

    if [[ ${#certs[@]} -eq 0 ]]; then
        error_exit "No certificates issued by the active CA were found."
    fi

#-----------------------------------
#Rebuild the index.txt
#-----------------------------------
    log "Rebuilding CRL index file: $crl_index_file"
    echo -e "# OpenSSL CRL index file\n#<status>\t<expiration>\t<revocation>\t<serial>\t<file>\t<subject>" > "$crl_index_file"

    for cert in "${certs[@]}"; do
        local serial expiry_date formatted_expiry_date subject
        serial=$(openssl x509 -in "$cert" -serial -noout | cut -d'=' -f2 | tr '[:lower:]' '[:upper:]')
        expiry_date=$(openssl x509 -in "$cert" -enddate -noout | cut -d'=' -f2)
        formatted_expiry_date=$(date -u -d "$expiry_date" +"%y%m%d%H%M%SZ")
        subject=$(openssl x509 -in "$cert" -subject -noout | sed 's/subject= //')

        printf "V\t%s\t\t%s\tunknown\t%s\n" "$formatted_expiry_date" "$serial" "$subject" >> "$crl_index_file"
    done

    log "CRL index rebuild completed successfully. Total certificates indexed: ${#certs[@]}"
}



update_crl() {
    local action="$1"    #"init", "add", "full", or "revoke"
    local cert_file="$2" #Path to the certificate file for "add" or "revoke"
    local reason="${3:-unspecified}"  # Default revocation reason

    log "Starting CRL update process (Action: $action)..."
    load_config

#Define file paths
    local crl_index_file="$CRL_DIR/index.txt"
    local crl_number_file="$CRL_DIR/crlnumber"
    local der_crl_file="$CRL_DIR/ca.crl"
    local pem_crl_file="$CRL_DIR/crl.pem"
    local strongswan_crl_link="/etc/swanctl/x509crl/crl.pem"
    local nginx_crl_link="/etc/nginx/crl/ca.crl"

#Ensure necessary directories and files exist
    log "Ensuring necessary directories and files exist..."
    mkdir -p "$CRL_DIR" /etc/swanctl/x509crl /etc/nginx/crl
    touch "$crl_index_file" "$crl_number_file"
    [[ ! -s "$crl_number_file" ]] && echo "01" > "$crl_number_file"

    if [[ "$action" == "init" ]]; then
        log "Initializing CRL index and number files..."
        mkdir -p "$CRL_DIR"

    #Initialize crlnumber file
        echo "01" > "$CRL_DIR/crlnumber"

    #Initialize index.txt file
        echo -e "# OpenSSL CRL index file\n#<status>\t<expiration>\t<revocation>\t<serial>\t<file>\t<subject>" > "$CRL_DIR/index.txt"

    #Initialize ca.srl file
        if [[ ! -f "$CRL_DIR/ca.srl" ]]; then
            echo "01" > "$CRL_DIR/ca.srl" || error_exit "Failed to initialize ca.srl file."
        fi

        log "CRL infrastructure initialized successfully."
        return
    fi

    if [[ "$action" == "add" && -n "$cert_file" ]]; then
        log "Adding new certificate entry to index.txt for: $cert_file..."

    #Validate certificate file
        if [[ ! -f "$cert_file" ]]; then
            error_exit "Certificate file $cert_file does not exist!"
        fi

        local serial expiry_date formatted_expiry_date subject
        serial=$(openssl x509 -in "$cert_file" -serial -noout | cut -d'=' -f2 | tr '[:lower:]' '[:upper:]')
        expiry_date=$(openssl x509 -in "$cert_file" -enddate -noout | cut -d'=' -f2)
        formatted_expiry_date=$(date -u -d "$expiry_date" +"%y%m%d%H%M%SZ")
        subject=$(openssl x509 -in "$cert_file" -subject -noout | sed 's/subject= //')

        log "Extracted serial: $serial"
        log "Extracted subject: $subject"
        log "Extracted expiry date: $formatted_expiry_date"

        if grep -iq "$serial" "$crl_index_file"; then
            log "Certificate entry already exists in index.txt."
        else
            printf "V\t%s\t\t%s\tunknown\t%s\n" "$formatted_expiry_date" "$serial" "$subject" >> "$crl_index_file"
            log "Certificate entry added to index.txt."
        fi
        return
    fi

    if [[ "$action" == "revoke" && -n "$cert_file" ]]; then
        log "Revoking certificate: $cert_file..."

    #Validate certificate file
        if [[ ! -f "$cert_file" ]]; then
            error_exit "Certificate file $cert_file does not exist!"
        fi

        local serial reason_code revocation_date
        serial=$(openssl x509 -in "$cert_file" -serial -noout | cut -d'=' -f2 | tr '[:lower:]' '[:upper:]')
        revocation_date=$(date -u +"%y%m%d%H%M%SZ")

    #Map reason to OpenSSL-compatible terms
        case "$reason" in
            superseded)
                reason_code="superseded"
                ;;
            keyCompromise)
                reason_code="keyCompromise"
                ;;
            affiliationChanged)
                reason_code="affiliationChanged"
                ;;
            cessationOfOperation)
                reason_code="cessationOfOperation"
                ;;
            certificateHold)
                reason_code="certificateHold"
                ;;
            unspecified)
                reason_code="unspecified"
                ;;
            *)
                reason_code="unspecified"  # Default
                ;;
        esac

    #Check if the serial exists in index.txt
        if grep -iq "$serial" "$crl_index_file"; then
            local line expire_date serial_field subject_field
            line=$(grep -i "$serial" "$crl_index_file")
            expire_date=$(echo "$line" | awk -F'\t' '{print $2}')
            serial_field=$(echo "$line" | awk -F'\t' '{print $4}')
            subject_field=$(echo "$line" | awk -F'\t' '{print $6}')

        #Remove old line
            sed -i "/$serial/I d" "$crl_index_file"

        #Add revoked line with reason
            printf "R\t%s\t%s,%s\t%s\tunknown\t%s\n" "$expire_date" "$revocation_date" "$reason_code" "$serial_field" "$subject_field" >> "$crl_index_file"
            log "Certificate revoked successfully with reason: $reason."
        else
            log "Certificate $serial not found in index.txt. Skipping revocation."
        fi
        return
    fi

    if [[ "$action" == "full" ]]; then
        log "Generating updated CRL using OpenSSL..."

    #Generate the CRL in PEM format
        if ! openssl ca -gencrl -config /etc/ssl/openssl.cnf -out "$pem_crl_file"; then
            error_exit "Failed to generate updated CRL."
        fi

        log "Converting updated CRL to DER format..."
    #Convert the CRL from PEM to DER format
        if ! openssl crl -in "$pem_crl_file" -outform DER -out "$der_crl_file"; then
            error_exit "Failed to convert CRL to DER format."
        fi

        log "Updating symlinks for CRL..."
    #Update symlinks to point to the latest CRL files
        ln -sf "$pem_crl_file" "$strongswan_crl_link"
        ln -sf "$der_crl_file" "$nginx_crl_link"

    #Optional service restart
        if [[ "$RESTART_SERVICES" == "true" ]]; then
            log "Restarting dependent services..."
            systemctl reload nginx || log "Failed to reload NGINX."
            if systemctl is-active --quiet ocsp-responder.service; then
                systemctl restart ocsp-responder.service || log "Failed to restart OCSP responder."
            fi
        fi

        log "CRL update process completed successfully."
    fi

    if [[ "$action" == "verify" ]]; then
        log "Verifying CRL integrity..."

    #Ensure CRL file exists
        if [[ ! -f "$pem_crl_file" ]]; then
            error_exit "PEM CRL file not found: $pem_crl_file"
        fi

    #Verify the CRL
        if openssl crl -in "$pem_crl_file" -inform PEM -noout -text; then
            log "CRL verification successful."
        else
            error_exit "CRL verification failed."
        fi
    fi
}


case $1 in
    check)
        check_environment
        ;;
    init)
        init_db
        ;;
    rebuild-crl)
        read -p "This will rebuild the CRL database. you will need to revoke users after rebuild are you sure? (y/n): " confirm
        [[ "$confirm" != "y" ]] && exit 0
        rebuild_crl
        ;;
    generate-ca)
        generate_ca
        ;;
   generate-crl)
    if [[ -z "$2" ]]; then
        read -p "Select update function (full|init|add|revoke): " update_type
    else
        update_type="$2"
    fi
    case "$update_type" in
        add|revoke)
            if [[ -z "$3" ]]; then
                if [[ "$update_type" == "revoke" ]]; then
                    read -p "Enter the certificate name to revoke (e.g., 'example' for /opt/pki/x509/example.pem): " cert_name
                    cert_file="/opt/pki/x509/${cert_name}.pem"
                else
                    read -p "Certificate file path: " cert_file
                fi
            else
                if [[ "$update_type" == "revoke" ]]; then
                    cert_file="/opt/pki/x509/${3}.pem"
                else
                    cert_file="$3"
                fi
            fi

            if [[ "$update_type" == "revoke" && -z "$4" ]]; then
                echo "Please provide the revocation reason (default: superseded):"
                echo "1) superseded"
                echo "2) keyCompromise"
                echo "3) affiliationChanged"
                echo "4) cessationOfOperation"
                echo "5) certificateHold"
                read -p "Enter the number corresponding to the reason: " reason_choice
                case "$reason_choice" in
                    1) reason="superseded" ;;
                    2) reason="keyCompromise" ;;
                    3) reason="affiliationChanged" ;;
                    4) reason="cessationOfOperation" ;;
                    5) reason="certificateHold" ;;
                    *) reason="superseded" ;;
                esac
            else
                reason="$4"
            fi

        #Check if the certificate file exists before passing it to update_crl
            if [[ ! -f "$cert_file" ]]; then
                error_exit "Certificate file not found: $cert_file"
            fi

            update_crl "$update_type" "$cert_file" "$reason"
            ;;
        *)
            update_crl "$update_type"
            ;;
    esac
    ;;
    generate-client)
        [ -z "$2" ] && error_exit "Client email is required for generate-client command"
        [ -z "$3" ] && error_exit "Duration (in months) is required for generate-client command"
        generate_client "$2" "$3"
        ;;
    import-csv)
        import_csv "$2"
        ;;
    revoke-client)
        [ -z "$2" ] && error_exit "Client email is required for revoke-client command"
        revoke_client "$2"
        ;;
    generate-server)
        generate_server
        ;;
    generate-ocsp-cert)
        generate_ocsp_cert
        ;;
    generate-custom-server)
        generate_custom_server
        ;;
    generate-csr)
        [ -z "$2" ] && error_exit "DNS_NAME is required for generate-csr command"
        [ -z "$3" ] && error_exit "Client type (internal|third-party) is required for generate-csr command"
        client_type="$3"
        dns_name="$2"
        if [[ "$client_type" == "internal" ]]; then
            generate_csr "internal" "$dns_name"
        elif [[ "$client_type" == "third-party" ]]; then
            generate_csr "third-party" "$dns_name"
        else
            error_exit "Invalid client type: $client_type. Use 'internal' or 'third-party'."
        fi
        ;;
    export-bundle)
        [ -z "$2" ] && error_exit "Client email is required for export-bundle command"
        export_bundle "$2"
        ;;
    generate-mobileconfig)
        [ -z "$2" ] && error_exit "Client name is required for generate-mobileconfig command"
        generate_mobileconfig "$2"
        ;;
    generate_powershell_script)
         [ -z "$2" ] && error_exit "Client name is required for generate-windowsconfig command"
        generate_powershell_script "$2"
        ;;  
    list)
        list_certs
        ;;
    set-permissions)
        set_permissions
        ;;    
    help)
        echo "Usage: $0 COMMAND [OPTIONS]"
        echo
        cat <<EOF
PKI Management:
    check           - Check environment and dependencies
    rebuild-crl     - Rebuild CRL database index.txt and number files

Server Certificates:
    generate-ca         - Create & Replace Certificate Authority
    generate-server     - Generate VPN CN=IP server certificate
    generate-ocsp-cert  - Create OCSP responder CN=IP certificate
    generate-csr DNS_NAME TYPE  - Generate CSR (internal|third-party)
    generate-custom-server      - Generate server CN=DNS name certificate

Client Certificates:
    import-csv CSV_FILE         - Import client certificates from CSV file
    generate-client EMAIL MONTHS - Create client certificate & set lifetime in months
    revoke-client EMAIL          - Revoke client certificate full crl update required
    export-bundle EMAIL          - Export client certificate bundle

CRL Management:
    to initialize the CRL system, add new certificates, and revoke existing ones.
    generate-crl OPTION
          Options:
            full
               Generates new CRL updates the CRL index & restarts ocsp responder
            init
              Initializes the CRL environment, setting up necessary configurations.
            add CERT_PATH
               Adds a new certificate to the CRL from the provided CERT_PATH.
            revoke CERT_NAME [REASON]
               Revokes the certificate identified by CERT_NAME with an optional REASON
            Revocation Reasons: 
                                1) superseded 2) keyCompromise 
                                3) affiliationChanged 4) cessationOfOperation 
                                5) certificateHold
Maintenance:
    list            - List all certificates
    set-permissions - Fix permissions for PKI directories & /etc/swanctl
EOF
    exit 1
    ;;
    *)
        error_exit "Invalid command: $1. Use 'help' for usage information."
        ;;
esac