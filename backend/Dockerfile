# MALINFO Backend - Production Dockerfile
# Multi-stage build for minimal, secure production image with full VM orchestration support
# Security hardened: non-root user, minimal attack surface, no secrets in image

# --- Build Stage ---
FROM python:3.11-slim as builder

# Install build dependencies
# Note: libvirt-python 10.6.0 requires libvirt C library >= 10.0.0
# Use libvirt-dev from debian bookworm (libvirt 9.x) - need to ensure compatibility
RUN apt-get update && apt-get install -y --no-install-recommends \
    gcc \
    libc6-dev \
    libmagic1 \
    libfuzzy-dev \
    libssl-dev \
    libvirt-dev \
    pkg-config \
    yara \
    libyara-dev \
    python3-dev \
    && rm -rf /var/lib/apt/lists/*

# Ensure pkg-config can find libvirt
ENV PKG_CONFIG_PATH=/usr/lib/x86_64-linux-gnu/pkgconfig:/usr/share/pkgconfig

# Set working directory
WORKDIR /app

# Install Python dependencies to user directory
COPY requirements.txt .
RUN pip install --no-cache-dir --user -r requirements.txt

# --- Runtime Stage ---
FROM python:3.11-slim

# Security: Add security labels
LABEL maintainer="MALINFO Team" \
      version="1.0.0-pilot" \
      description="MALINFO Backend API" \
      security.scan="true"

# Install runtime dependencies including libvirt/qemu for VM orchestration
RUN apt-get update && apt-get install -y --no-install-recommends \
    libmagic1 \
    libfuzzy2 \
    libssl3 \
    libvirt0 \
    libvirt-glib-1.0-0 \
    libxml2 \
    yara \
    libffi8 \
    ca-certificates \
    iproute2 \
    net-tools \
    iputils-ping \
    curl \
    dumb-init \
    && rm -rf /var/lib/apt/lists/* \
    && apt-get clean \
    && rm -rf /var/cache/apt/*

# Create non-root user with proper groups for libvirt/kvm access
# Use fixed UID/GID for consistency
RUN groupadd -r -g 998 libvirt && \
    groupadd -r -g 997 kvm && \
    groupadd -r -g 996 malinfo && \
    useradd -r -u 996 -g malinfo -G libvirt,kvm -d /home/malinfo -m -s /bin/bash malinfo

# Set working directory
WORKDIR /app

# Copy Python packages from builder
COPY --from=builder /root/.local /home/malinfo/.local

# Copy application code with correct ownership
COPY --chown=malinfo:malinfo app ./app
COPY --chown=malinfo:malinfo requirements.txt .

# Create storage directories with proper permissions
RUN mkdir -p /app/storage/uploads /app/storage/reports /app/storage/pcaps \
    /app/storage/vms /app/storage/isos \
    && chown -R malinfo:malinfo /app

# Switch to non-root user
USER malinfo

# Add user packages to PATH
ENV PATH=/home/malinfo/.local/bin:$PATH \
    PYTHONUNBUFFERED=1 \
    PYTHONDONTWRITEBYTECODE=1 \
    MALINFO_ENV=production \
    LIBVIRT_DEFAULT_URI=qemu:///system

# Security: Remove unnecessary capabilities
# The container runs as non-root, so most capabilities are not needed

# Health check - uses the app's health endpoint
HEALTHCHECK --interval=30s --timeout=10s --start-period=40s --retries=3 \
    CMD curl -f http://localhost:8000/api/health || exit 1

# Expose port
EXPOSE 8000

# Use dumb-init to handle signals properly
ENTRYPOINT ["dumb-init", "--"]

# Run application with gunicorn for production (4 workers)
CMD ["gunicorn", "app.main:app", "--workers", "4", "--worker-class", "uvicorn.workers.UvicornWorker", "--bind", "0.0.0.0:8000", "--timeout", "300", "--access-logfile", "-", "--error-logfile", "-"]