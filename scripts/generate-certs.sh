#!/usr/bin/env bash
# MALINFO — TLS Certificate Generator
# Supports: self-signed (dev/staging) and Let's Encrypt (production)

set -euo pipefail

CERT_DIR="${1:-./deploy/certs}"
MODE="${2:-selfsigned}"  # selfsigned | letsencrypt
DOMAIN="${3:-malinfo.example.gov}"
EMAIL="${4:-admin@example.gov}"

mkdir -p "$CERT_DIR"

echo "=========================================="
echo "MALINFO TLS Certificate Generator"
echo "=========================================="
echo "Mode: $MODE"
echo "Domain: $DOMAIN"
echo "Cert Dir: $CERT_DIR"
echo ""

if [[ "$MODE" == "selfsigned" ]]; then
    echo "Generating self-signed certificate for development/staging..."
    
    # Generate private key
    openssl genrsa -out "$CERT_DIR/privkey.pem" 2048
    
    # Generate CSR
    openssl req -new -key "$CERT_DIR/privkey.pem" -out "$CERT_DIR/csr.pem" \
        -subj "/CN=$DOMAIN" \
        -addext "subjectAltName=DNS:$DOMAIN,DNS:*.malinfo.example.gov,IP:127.0.0.1"
    
    # Generate self-signed certificate (valid 1 year)
    openssl x509 -req -in "$CERT_DIR/csr.pem" -signkey "$CERT_DIR/privkey.pem" \
        -out "$CERT_DIR/fullchain.pem" -days 365 \
        -extfile <(echo -e "subjectAltName=DNS:$DOMAIN,DNS:*.malinfo.example.gov,IP:127.0.0.1\nextendedKeyUsage=serverAuth")
    
    # Copy for nginx
    cp "$CERT_DIR/fullchain.pem" "$CERT_DIR/chain.pem"
    
    echo "✅ Self-signed certificates generated:"
    echo "   $CERT_DIR/privkey.pem"
    echo "   $CERT_DIR/fullchain.pem"
    echo "   $CERT_DIR/chain.pem"
    echo ""
    echo "⚠️  Browsers will show security warning for self-signed certs."
    echo "   For production, use: $0 $CERT_DIR letsencrypt $DOMAIN $EMAIL"
    
elif [[ "$MODE" == "letsencrypt" ]]; then
    echo "Setting up Let's Encrypt certificates..."
    
    # Check if certbot is available
    if ! command -v certbot &> /dev/null; then
        echo "Installing certbot..."
        if command -v apt-get &> /dev/null; then
            apt-get update && apt-get install -y certbot
        elif command -v yum &> /dev/null; then
            yum install -y certbot
        elif command -v brew &> /dev/null; then
            brew install certbot
        else
            echo "❌ Please install certbot manually"
            exit 1
        fi
    fi
    
    # Stop nginx if running on port 80 (for standalone challenge)
    echo "Running certbot standalone challenge..."
    certbot certonly --standalone \
        --non-interactive \
        --agree-tos \
        --email "$EMAIL" \
        -d "$DOMAIN" \
        -d "*.malinfo.example.gov" \
        --cert-path "$CERT_DIR/fullchain.pem" \
        --key-path "$CERT_DIR/privkey.pem" \
        --chain-path "$CERT_DIR/chain.pem"
    
    # Copy to expected locations
    cp "/etc/letsencrypt/live/$DOMAIN/fullchain.pem" "$CERT_DIR/fullchain.pem"
    cp "/etc/letsencrypt/live/$DOMAIN/privkey.pem" "$CERT_DIR/privkey.pem"
    cp "/etc/letsencrypt/live/$DOMAIN/chain.pem" "$CERT_DIR/chain.pem"
    
    # Set up auto-renewal
    echo "Setting up auto-renewal cron job..."
    (crontab -l 2>/dev/null; echo "0 3 * * * certbot renew --quiet --post-hook 'cp /etc/letsencrypt/live/$DOMAIN/*.pem $CERT_DIR/ && docker compose -f /opt/malinfo/docker-compose.prod.yml restart nginx'") | crontab -
    
    echo "✅ Let's Encrypt certificates installed and auto-renewal configured"
    
else
    echo "❌ Unknown mode: $MODE"
    echo "Usage: $0 [cert_dir] [selfsigned|letsencrypt] [domain] [email]"
    exit 1
fi

echo ""
echo "=========================================="
echo "Certificate Details:"
echo "=========================================="
openssl x509 -in "$CERT_DIR/fullchain.pem" -text -noout | head -20