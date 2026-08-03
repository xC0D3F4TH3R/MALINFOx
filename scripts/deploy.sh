#!/usr/bin/env bash
# MALINFO — Production Deployment Script
# Supports: Docker Compose, Kubernetes, systemd (bare metal)

set -euo pipefail

# Configuration
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(dirname "$SCRIPT_DIR")"
DEPLOY_MODE="${1:-docker}"  # docker | k8s | systemd
ACTION="${2:-up}"           # up | down | restart | logs | status | backup | restore
PROFILE="${3:-}"            # monitoring | icap | monitor | all

# Colors
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m'

log_info() { echo -e "${BLUE}[INFO]${NC} $*"; }
log_success() { echo -e "${GREEN}[SUCCESS]${NC} $*"; }
log_warn() { echo -e "${YELLOW}[WARN]${NC} $*"; }
log_error() { echo -e "${RED}[ERROR]${NC} $*"; }

# Load environment
load_env() {
    local env_file="$PROJECT_ROOT/.env"
    if [[ ! -f "$env_file" ]]; then
        log_error "Environment file not found: $env_file"
        log_info "Run: cp .env.example .env && edit .env"
        exit 1
    fi
    set -a
    source "$env_file"
    set +a
    log_info "Loaded environment from $env_file"
}

# Check prerequisites
check_prereqs() {
    local mode="$1"
    case "$mode" in
        docker)
            command -v docker >/dev/null 2>&1 || { log_error "Docker not installed"; exit 1; }
            command -v docker compose >/dev/null 2>&1 || { log_error "Docker Compose not installed"; exit 1; }
            ;;
        k8s)
            command -v kubectl >/dev/null 2>&1 || { log_error "kubectl not installed"; exit 1; }
            command -v helm >/dev/null 2>&1 || { log_warn "Helm not installed (optional)"; }
            ;;
        systemd)
            [[ $EUID -eq 0 ]] || { log_error "systemd deployment requires root"; exit 1; }
            command -v systemctl >/dev/null 2>&1 || { log_error "systemd not available"; exit 1; }
            ;;
    esac
}

# Docker Compose deployment
deploy_docker() {
    local action="$1"
    local profile_args=""
    
    case "$PROFILE" in
        monitoring) profile_args="--profile monitoring" ;;
        icap) profile_args="--profile icap" ;;
        monitor) profile_args="--profile monitor" ;;
        all) profile_args="--profile monitoring --profile icap --profile monitor" ;;
    esac
    
    cd "$PROJECT_ROOT"
    
    case "$action" in
        up)
            log_info "Starting MALINFO with Docker Compose..."
            docker compose -f docker-compose.prod.yml $profile_args up -d --build
            log_success "MALINFO started. Run 'deploy.sh docker logs' to follow logs."
            ;;
        down)
            log_info "Stopping MALINFO..."
            docker compose -f docker-compose.prod.yml $profile_args down
            ;;
        restart)
            docker compose -f docker-compose.prod.yml $profile_args restart
            ;;
        logs)
            docker compose -f docker-compose.prod.yml $profile_args logs -f --tail=100
            ;;
        status)
            docker compose -f docker-compose.prod.yml $profile_args ps
            ;;
        backup)
            backup_docker
            ;;
        restore)
            restore_docker "${4:-}"
            ;;
        *)
            log_error "Unknown action: $action"
            exit 1
            ;;
    esac
}

# Kubernetes deployment
deploy_k8s() {
    local action="$1"
    
    case "$action" in
        up)
            log_info "Deploying MALINFO to Kubernetes..."
            kubectl apply -f "$PROJECT_ROOT/deploy/kubernetes/malinfo-platform.yaml"
            log_success "Deployed. Check status with: deploy.sh k8s status"
            ;;
        down)
            log_info "Removing MALINFO from Kubernetes..."
            kubectl delete -f "$PROJECT_ROOT/deploy/kubernetes/malinfo-platform.yaml" --ignore-not-found=true
            ;;
        restart)
            kubectl rollout restart deployment/malinfo-backend -n malinfo
            kubectl rollout restart deployment/malinfo-nginx -n malinfo
            ;;
        logs)
            kubectl logs -f deployment/malinfo-backend -n malinfo --tail=100
            ;;
        status)
            kubectl get all -n malinfo
            ;;
        backup)
            backup_k8s
            ;;
        restore)
            restore_k8s "${4:-}"
            ;;
        *)
            log_error "Unknown action: $action"
            exit 1
            ;;
    esac
}

# systemd deployment
deploy_systemd() {
    local action="$1"
    
    case "$action" in
        up)
            log_info "Installing MALINFO systemd services..."
            cp "$PROJECT_ROOT/deploy/malinfo-backend.service" /etc/systemd/system/
            cp "$PROJECT_ROOT/deploy/malinfo-icap.service" /etc/systemd/system/
            cp "$PROJECT_ROOT/deploy/malinfo-monitor.service" /etc/systemd/system/
            systemctl daemon-reload
            systemctl enable --now malinfo-backend malinfo-icap malinfo-monitor
            log_success "Services installed and started"
            ;;
        down)
            systemctl stop malinfo-backend malinfo-icap malinfo-monitor
            systemctl disable malinfo-backend malinfo-icap malinfo-monitor
            rm -f /etc/systemd/system/malinfo-*.service
            systemctl daemon-reload
            ;;
        restart)
            systemctl restart malinfo-backend malinfo-icap malinfo-monitor
            ;;
        logs)
            journalctl -u malinfo-backend -u malinfo-icap -u malinfo-monitor -f --tail=100
            ;;
        status)
            systemctl status malinfo-backend malinfo-icap malinfo-monitor --no-pager
            ;;
        *)
            log_error "Unknown action: $action"
            exit 1
            ;;
    esac
}

# Backup functions
backup_docker() {
    local backup_dir="${BACKUP_DIR:-/opt/malinfo/backups}"
    local timestamp=$(date +%Y%m%d_%H%M%S)
    local backup_file="$backup_dir/malinfo_backup_$timestamp.tar.gz"
    
    mkdir -p "$backup_dir"
    log_info "Creating backup: $backup_file"
    
    # Backup database
    docker compose -f docker-compose.prod.yml exec -T db pg_dump -U malinfo malinfo | gzip > "$backup_dir/db_$timestamp.sql.gz"
    
    # Backup storage
    docker run --rm -v malinfo_storage:/data -v "$backup_dir":/backup alpine tar czf "/backup/storage_$timestamp.tar.gz" -C /data .
    
    # Backup configs
    tar czf "$backup_file" -C "$PROJECT_ROOT" .env docker-compose.prod.yml deploy/
    
    log_success "Backup completed: $backup_file"
}

restore_docker() {
    local backup_file="$1"
    [[ -f "$backup_file" ]] || { log_error "Backup file not found: $backup_file"; exit 1; }
    
    log_warn "This will overwrite current data. Continue? (y/N)"
    read -r confirm
    [[ "$confirm" == "y" ]] || exit 1
    
    log_info "Restoring from $backup_file..."
    docker compose -f docker-compose.prod.yml down
    
    # Restore configs
    tar xzf "$backup_file" -C "$PROJECT_ROOT"
    
    # Restore database
    local db_dump=$(ls -t /opt/malinfo/backups/db_*.sql.gz 2>/dev/null | head -1)
    [[ -f "$db_dump" ]] && {
        docker compose -f docker-compose.prod.yml up -d db
        sleep 10
        gunzip -c "$db_dump" | docker compose -f docker-compose.prod.yml exec -T db psql -U malinfo malinfo
    }
    
    # Restore storage
    local storage_backup=$(ls -t /opt/malinfo/backups/storage_*.tar.gz 2>/dev/null | head -1)
    [[ -f "$storage_backup" ]] && {
        docker run --rm -v malinfo_storage:/data -v "$(dirname "$storage_backup")":/backup alpine tar xzf "/backup/$(basename "$storage_backup")" -C /data
    }
    
    docker compose -f docker-compose.prod.yml up -d
    log_success "Restore completed"
}

backup_k8s() {
    log_info "Kubernetes backup - use Velero or etcd backup for production"
    kubectl get all -n malinfo -o yaml > "/opt/malinfo/backups/k8s_resources_$(date +%Y%m%d_%H%M%S).yaml"
}

restore_k8s() {
    local backup_file="$1"
    [[ -f "$backup_file" ]] || { log_error "Backup file not found"; exit 1; }
    kubectl apply -f "$backup_file"
}

# Health check
health_check() {
    local url="${MALINFO_URL:-https://localhost/api/health}"
    log_info "Checking health at $url..."
    
    for i in {1..30}; do
        if curl -kfs "$url" >/dev/null 2>&1; then
            log_success "Health check passed"
            curl -ks "$url" | jq .
            return 0
        fi
        sleep 2
    done
    log_error "Health check failed after 60 seconds"
    return 1
}

# Initialize project
init_project() {
    log_info "Initializing MALINFO project..."
    
    # Generate secrets if not exist
    if [[ ! -f "$PROJECT_ROOT/.env" ]]; then
        log_info "Creating .env from template..."
        cp "$PROJECT_ROOT/.env.example" "$PROJECT_ROOT/.env"
        log_warn "Edit .env with your configuration before deploying!"
    fi
    
    # Generate certs if not exist
    if [[ ! -f "$PROJECT_ROOT/deploy/certs/fullchain.pem" ]]; then
        log_info "Generating self-signed certificates..."
        "$SCRIPT_DIR/generate-certs.sh" "$PROJECT_ROOT/deploy/certs" selfsigned
    fi
    
    # Create YARA rules directory structure
    mkdir -p "$PROJECT_ROOT/backend/app/rules/yara"/{sources,compiled,feeds,test_cases}
    log_info "Created YARA rules directory structure"
    
    # Create storage directories
    mkdir -p "$PROJECT_ROOT/backend/storage"/{uploads,reports,pcaps}
    log_info "Created storage directories"
    
    log_success "Project initialized. Edit .env and run: deploy.sh docker up"
}

# Main
main() {
    echo "=========================================="
    echo "MALINFO Production Deployment"
    echo "=========================================="
    echo "Mode: $DEPLOY_MODE"
    echo "Action: $ACTION"
    [[ -n "$PROFILE" ]] && echo "Profile: $PROFILE"
    echo ""
    
    case "$ACTION" in
        init)
            init_project
            ;;
        health)
            load_env
            health_check
            ;;
        *)
            load_env
            check_prereqs "$DEPLOY_MODE"
            case "$DEPLOY_MODE" in
                docker) deploy_docker "$ACTION" ;;
                k8s) deploy_k8s "$ACTION" ;;
                systemd) deploy_systemd "$ACTION" ;;
                *) log_error "Unknown deploy mode: $DEPLOY_MODE"; exit 1 ;;
            esac
            ;;
    esac
}

main "$@"