#!/bin/bash
set -e

# Load common utilities
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
SCRIPT_NAME="DOCKER-ENTRYPOINT"

DOMAIN="${DOMAIN:-}"
THUMBOR_HOST="${THUMBOR_HOST:-}"
CERT_DIR="/etc/letsencrypt/live/${DOMAIN}"
CERT_FILE="${CERT_DIR}/fullchain.pem"
KEY_FILE="${CERT_DIR}/privkey.pem"
NGINX_CONF_TPL="/etc/nginx/host.conf.tpl"
NGINX_CONF_AVAILABLE="/etc/nginx/sites-available/${DOMAIN}.conf"
NGINX_CONF_ENABLED="/etc/nginx/sites-enabled/${DOMAIN}.conf"
WEBROOT="/var/www/certbot"
RENEWAL_DAYS=1

# Source common utilities
source "${SCRIPT_DIR}/common-utils.sh"

logs() {
    info "Checking and creating log directories..."
    
    # Array of log directories to check/create
    local log_dirs=(
        "/var/log/nginx"
        "/var/log/supervisor"
        "/var/log/system"
    )
    
    # Check each directory
    for dir in "${log_dirs[@]}"; do
        if [[ ! -d "$dir" ]]; then
            info "Creating log directory: $dir"
            if safe_execute "mkdir -p '$dir'" "Creating directory $dir"; then
                debug "Directory $dir created successfully"
                
                # Set permissions to 755 for directories
                if safe_execute "chmod 755 '$dir'" "Setting permissions for $dir"; then
                    debug "Permissions set to 755 for $dir"
                else
                    warning "Failed to set permissions for $dir"
                fi
                
                # Set proper ownership based on directory type
                if [[ "$dir" == "/var/log/supervisor" || "$dir" == "/var/log/system" ]]; then
                    # Supervisor and system logs should be owned by root
                    if safe_execute "chown root:root '$dir'" "Setting ownership for $dir"; then
                        debug "Ownership set to root:root for $dir"
                    else
                        warning "Failed to set ownership for $dir"
                    fi
                else
                    # Other logs should be owned by www-data
                    if safe_execute "chown www-data:www-data '$dir'" "Setting ownership for $dir"; then
                        debug "Ownership set to www-data:www-data for $dir"
                    else
                        warning "Failed to set ownership for $dir"
                    fi
                fi
            else
                error "Failed to create directory $dir"
            fi
        else
            debug "Log directory already exists: $dir"
        fi
    done
    
    success "Log directories check completed"
}

# Function to generate DH parameters for SSL
generate_dhparam() {
    local dhparam_file="/etc/ssl/certs/dhparam.pem"
    
    info "Checking DH parameters file..."
    
    if [ ! -f "$dhparam_file" ]; then
        info "Generating DH parameters (2048-bit) for SSL - this may take a few minutes..."
        if safe_execute "openssl dhparam -out '$dhparam_file' 2048" "Generating DH parameters"; then
            success "DH parameters generated successfully at $dhparam_file"
            
            # Set proper permissions
            if safe_execute "chmod 644 '$dhparam_file'" "Setting DH parameters permissions"; then
                debug "DH parameters permissions set successfully"
            else
                warning "Failed to set DH parameters permissions"
            fi
        else
            error "Failed to generate DH parameters"
            return 1
        fi
    else
        info "DH parameters file already exists at $dhparam_file"
    fi
}

# Function to generate QUIC host key for HTTP/3
generate_quic_key() {
    local quic_key_file="/etc/ssl/certs/quic_host_key"
    
    info "Checking QUIC host key file..."
    
    if [ ! -f "$quic_key_file" ]; then
        info "Generating QUIC host key for HTTP/3..."
        
        # Create directory if it doesn't exist
        if safe_execute "mkdir -p /etc/ssl/certs" "Creating SSL certificates directory"; then
            debug "SSL certificates directory created/verified"
        else
            error "Failed to create SSL certificates directory"
            return 1
        fi
        
        # Generate random 32-byte key for QUIC
        if safe_execute "openssl rand -out '$quic_key_file' 32" "Generating QUIC host key"; then
            success "QUIC host key generated successfully at $quic_key_file"
            
            # Set proper permissions (read/write for root only)
            if safe_execute "chmod 600 '$quic_key_file'" "Setting QUIC key permissions"; then
                debug "QUIC key permissions set successfully"
            else
                warning "Failed to set QUIC key permissions"
            fi
            
            # Set proper ownership
            if safe_execute "chown root:root '$quic_key_file'" "Setting QUIC key ownership"; then
                debug "QUIC key ownership set successfully"
            else
                warning "Failed to set QUIC key ownership"
            fi
        else
            error "Failed to generate QUIC host key"
            return 1
        fi
    else
        info "QUIC host key file already exists at $quic_key_file"
    fi
}

# Function to generate CA certificates if they don't exist
generate_ca() {
    local ca_cert_file="/etc/ssl/certs/ca-certificates.crt"
    
    info "Checking CA certificates bundle..."
    
    if [[ ! -f "$ca_cert_file" ]] || [[ ! -r "$ca_cert_file" ]]; then
        info "Generating CA certificates bundle..."
        
        # Update ca-certificates bundle
        if safe_execute "update-ca-certificates" "Updating CA certificates"; then
            success "CA certificates updated successfully"
        else
            warning "Failed to update CA certificates"
        fi
        
        # Rehash SSL certificates directory
        if safe_execute "c_rehash /etc/ssl/certs" "Rehashing SSL certificates"; then
            success "SSL certificates rehashed successfully"
        else
            warning "Failed to rehash SSL certificates"
        fi
        
        # Try to create ca-certificates.crt from ca-bundle.crt if it exists and ca-certificates.crt is still missing
        if [[ ! -f "$ca_cert_file" ]] && [[ -f "/etc/ssl/certs/ca-bundle.crt" ]]; then
            if safe_execute "cp /etc/ssl/certs/ca-bundle.crt $ca_cert_file" "Creating ca-certificates.crt from ca-bundle.crt"; then
                success "Created ca-certificates.crt from ca-bundle.crt"
            else
                error "Failed to create ca-certificates.crt"
                return 1
            fi
        fi
        
        # Set proper permissions if file exists
        if [[ -f "$ca_cert_file" ]]; then
            if safe_execute "chmod 644 $ca_cert_file" "Setting CA certificates permissions"; then
                success "CA certificates permissions set successfully"
            else
                warning "Failed to set CA certificates permissions"
            fi
            
            # Verify certificate count
            local cert_count
            if cert_count=$(grep -c "BEGIN CERTIFICATE" "$ca_cert_file" 2>/dev/null); then
                success "CA certificates bundle contains $cert_count certificates"
            else
                warning "Could not count certificates in bundle"
            fi
        else
            error "CA certificates bundle still not found after generation"
            return 1
        fi
    else
        info "CA certificates bundle already exists at $ca_cert_file"
    fi
}

# Function to check if domain is defined
check_domain() {
    if [[ -z "$DOMAIN" ]]; then
        critical "DOMAIN environment variable is not defined"
        exit 1
    fi
    info "Configured domain: $DOMAIN"
}

# Function to check if certificate exists and is valid
check_certificate() {
    info "Checking certificate for $DOMAIN..."
    
    if [[ ! -f "$CERT_FILE" ]] || [[ ! -f "$KEY_FILE" ]]; then
        warning "Certificate not found for $DOMAIN"
        return 1
    fi
    
    # Check if certificate is valid and doesn't expire in the next RENEWAL_DAYS days
    local expiry_date
    expiry_date=$(openssl x509 -enddate -noout -in "$CERT_FILE" | cut -d= -f2)
    local expiry_timestamp
    expiry_timestamp=$(date -d "$expiry_date" +%s)
    local current_timestamp
    current_timestamp=$(date +%s)
    local renewal_timestamp
    renewal_timestamp=$((current_timestamp + (RENEWAL_DAYS * 24 * 3600)))
    
    if [[ $expiry_timestamp -lt $renewal_timestamp ]]; then
        warning "Certificate expires in less than $RENEWAL_DAYS days (expires on: $expiry_date)"
        return 1
    fi
    
    success "Certificate valid until: $expiry_date"
    return 0
}

# Function to create/renew certificate
create_or_renew_certificate() {
    info "Creating/renewing certificate for $DOMAIN..."
    
    # Create webroot directory if it doesn't exist
    safe_execute "mkdir -p '$WEBROOT'" "Creating webroot directory"
    
    # Check if certbot is installed
    if ! command_exists certbot; then
        critical "certbot is not installed"
        exit 1
    fi
        
    # Execute certbot
    if safe_execute "certbot certonly --standalone --non-interactive --agree-tos --email 'root@${DOMAIN}' --domains '$DOMAIN' --cert-name '$DOMAIN'" "Running certbot"; then
        success "Certificate created/renewed successfully for $DOMAIN"
    else
        error "Failed to create/renew certificate for $DOMAIN"
        exit 1
    fi
}

# Function to configure nginx
configure_nginx() {
    info "Configuring nginx for $DOMAIN..."

    # Host
    ## Check if template exists
    if ! file_readable "$NGINX_CONF_TPL"; then
        critical "Template $NGINX_CONF_TPL not found or not readable"
        exit 1
    fi
    
    ## Create necessary directories
    safe_execute "mkdir -p /etc/nginx/sites-available" "Creating sites-available directory"
    safe_execute "mkdir -p /etc/nginx/sites-enabled" "Creating sites-enabled directory"
    
    ## Replace placeholders in template and create configuration
    if safe_execute "sed -e 's/{{DOMAIN}}/$DOMAIN/g' '$NGINX_CONF_TPL' > '$NGINX_CONF_AVAILABLE'" "Creating nginx configuration"; then
        success "Configuration created at $NGINX_CONF_AVAILABLE"
    else
        error "Failed to create nginx configuration"
        exit 1
    fi
    
    ## Create symbolic link if it doesn't exist
    if [[ ! -L "$NGINX_CONF_ENABLED" ]]; then
        if safe_execute "ln -sf '$NGINX_CONF_AVAILABLE' '$NGINX_CONF_ENABLED'" "Creating symbolic link"; then
            success "Symbolic link created: $NGINX_CONF_ENABLED"
        else
            error "Failed to create symbolic link"
            exit 1
        fi
    fi
}

# Thumbor
configure_thumbor() {
    # To disable warning libdc1394 error: Failed to initialize libdc1394
    ln -s /dev/null /dev/raw1394

    # Generate thumbor configuration from template
    if [ ! -f /app/thumbor.conf ]; then
    envtpl /app/thumbor.conf.tpl --allow-missing --keep-template
    fi

    # Set default environment variables if not provided
    export THUMBOR_LOG_LEVEL=${THUMBOR_LOG_LEVEL:-info}
    export THUMBOR_NUM_PROCESSES=${THUMBOR_NUM_PROCESSES:-4}
}

# Main function
main() {
    # Log script start
    log_script_start "Docker Entrypoint"

    # Update SSL certificates first
    if generate_ca; then
        success "SSL certificates update completed successfully"
    else
        error "SSL certificates update failed"
        exit 1
    fi

    # Generate DH parameters for SSL
    if generate_dhparam; then
        success "SSL DH parameters setup completed successfully"
    else
        error "SSL DH parameters setup failed"
        exit 1
    fi
    
    # Generate QUIC host key for HTTP/3
    if generate_quic_key; then
        success "QUIC host key setup completed successfully"
    else
        error "QUIC host key setup failed"
        exit 1
    fi
    
    # Check required environment variables
    require_env_vars DOMAIN

    logs

    check_domain
    
    # Check and create/renew certificate if necessary
    if ! check_certificate; then
        create_or_renew_certificate
    fi
    
    # Configure Thumbor
    configure_thumbor

    # Configure nginx
    configure_nginx
    
    # Log script end
    log_script_end 0 "Docker Entrypoint"
    
    # Execute the original command
    info "Executing command: $*"
    exec "$@"
}

# Execute main function
main "$@"