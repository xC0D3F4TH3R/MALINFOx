#!/usr/bin/env bash
# MALINFO — Secrets Generator
# Generates all required secrets for production deployment
# Run this once during initial setup, store outputs in your secrets manager

set -euo pipefail

echo "=========================================="
echo "MALINFO Production Secrets Generator"
echo "=========================================="
echo ""

# Generate SECRET_KEY (32+ chars, base64)
SECRET_KEY=$(openssl rand -base64 48 | tr -d '\n')
echo "SECRET_KEY=${SECRET_KEY}"

# Generate POSTGRES_PASSWORD (strong password)
POSTGRES_PASSWORD=$(openssl rand -base64 32 | tr -d '\n' | tr -d '=/+')
echo "POSTGRES_PASSWORD=${POSTGRES_PASSWORD}"

# Generate GRAFANA_PASSWORD
GRAFANA_PASSWORD=$(openssl rand -base64 24 | tr -d '\n' | tr -d '=/+')
echo "GRAFANA_PASSWORD=${GRAFANA_PASSWORD}"

# Generate API keys placeholders (user must fill in real ones)
echo ""
echo "# Threat Intelligence API Keys (obtain from providers)"
echo "VIRUSTOTAL_API_KEY=your_virustotal_api_key_here"
echo "OTX_API_KEY=your_otx_api_key_here"
echo "ABUSEIPDB_API_KEY=your_abuseipdb_api_key_here"
echo "MISP_URL=https://your-misp-instance.example.com"
echo "MISP_API_KEY=your_misp_api_key_here"

echo ""
echo "=========================================="
echo "IMPORTANT: Save these secrets securely!"
echo "=========================================="
echo ""
echo "Add to your secrets manager (Vault, AWS Secrets Manager, etc.):"
echo "  - SECRET_KEY"
echo "  - POSTGRES_PASSWORD"
echo "  - GRAFANA_PASSWORD"
echo "  - VIRUSTOTAL_API_KEY"
echo "  - OTX_API_KEY"
echo "  - ABUSEIPDB_API_KEY"
echo "  - MISP_URL"
echo "  - MISP_API_KEY"
echo ""
echo "For Docker Compose, create .env file with these values."
echo "For Kubernetes, create secret 'malinfo-secrets' with these values."