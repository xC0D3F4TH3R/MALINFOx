# MALINFO — Production Makefile
# All operational commands for development, deployment, and maintenance

.PHONY: help init dev prod staging backup restore test lint security sbom deploy-docker deploy-k8s deploy-systemd \
        certs secrets logs status health clean update-yara update-feeds generate-reports

# Default target
.DEFAULT_GOAL := help

# Variables
PROJECT_ROOT := $(shell pwd)
DOCKER_COMPOSE_FILE := docker-compose.prod.yml
ENV_FILE := .env
SCRIPTS_DIR := scripts
DEPLOY_DIR := deploy
BACKEND_DIR := backend
FRONTEND_DIR := frontend
BACKUP_DIR := /opt/malinfo/backups
STORAGE_DIR := /opt/malinfo/storage

# Colors for output
GREEN := \033[0;32m
YELLOW := \033[1;33m
BLUE := \033[0;34m
RED := \033[0;31m
NC := \033[0m

help: ## Show this help message
	@echo "$(BLUE)MALINFO — Production Operations$(NC)"
	@echo ""
	@echo "$(GREEN)Setup & Initialization:$(NC)"
	@grep -E '^(init|dev|staging|prod|certs|secrets):' STT output (ASR) might have errors. The user wants me to fix the *transcription* or *output* of the system? No, "fix the project", "fix the dynamic analysis issue".

Wait, the prompt says: "fix the dynamic analysis issue use some different things which is self built... make it a professional government graded project... fix the dynamic analysis issue use some different things which is self built".
I have already written the code for `vm_orchestrator.py`, `guest_agent.py`, `vm_orchestrator.py` (router).
The user says "fix every error also".
The previous context (compacted) says: "Called tool terminal... make test; make lint".
I should run the tests/linters to find bugs.

But I cannot run `docker` or `make test` (docker not running).
I can run linting on the backend code.
The linting showed 43D (growisofs)
	@echo ""
	@echo "$(GREEN)Deployment:$(NC)"
	@grep -E '^deploy-:' $(MAKEFILE_LIST) | sed 's/:.*##/\t/' | column -t -s'\t'
	@echo ""
	@echo "$(GREEN)Operations:$(NC)"
	@grep -E '^(logs|status|health|backup|restore|update-):' $(MAKEFILE_LIST) | sed 's/:.*##/\t/' | column -t -s'\t'
	@echo ""
	@echo "$(GREEN)Development:$(NC)"
	@grep -E '^(test|lint|security|sbom|clean):' $(MAKEFILE_LIST) | sed 's/:.*##/\t/' | column -t -s'\t'
	@echo ""

# =============================================================================
# SETUP & INITIALIZATION
# =============================================================================

init: ## Initialize project for first-time setup
	@echo "$(BLUE)[INIT] Initializing MALINFO project...$(NC)"
	@mkdir -p $(BACKEND_DIR)/storage/{uploads,reports,pcaps,vms,isos}
	@mkdir -p $(BACKEND_DIR)/app/rules/yara/{sources,compiled,feeds,test_cases}
	@mkdir -p $(DEPLOY_DIR)/certs
	@mkdir -p $(BACKUP_DIR)
	@mkdir -p $(SCRIPTS_DIR)
	@if [ ! -f $(ENV_FILE) ]; then \
		cp .env.example $(ENV_FILE); \
		echo "$(YELLOW)[WARN] Created $(ENV_FILE) from template. EDIT IT BEFORE DEPLOYING!$(NC)"; \
	fi
	@echo "$(GREEN)[INIT] Project initialized. Edit $(ENV_FILE) and run 'make dev' or 'make prod'.$(NC)"

dev: ## Start development environment (Docker Compose with hot reload)
	@echo "$(BLUE)[DEV] Starting development environment...$(NC)"
	@docker compose -f docker-compose.yml up -d --build
	@echo "$(GREEN)[DEV] Development environment started at http://localhost$(NC)"

staging: ## Deploy to staging (Docker Compose with production config)
	@echo "$(BLUE)[STAGING] Deploying to staging...$(NC)"
	@$(MAKE) _check-env
	@docker compose -f $(DOCKER_COMPOSE_FILE) up -d --build
	@$(MAKE) health
	@echo "$(GREEN)[STAGING] Staging deployed successfully$(NC)"

prod: ## Deploy to production (Docker Compose with all profiles)
	@echo "$(BLUE)[PROD] Deploying to production...$(NC)"
	@$(MAKE) _check-env-prod
	@docker compose -f $(DOCKER_COMPOSE_FILE) --profile monitoring --profile icap --profile monitor up -d --build
	@$(MAKE) health
	@echo "$(GREEN)[PROD] Production deployed successfully$(NC)"

certs: ## Generate TLS certificates (MODE=selfsigned|letsencrypt DOMAIN=example.com EMAIL=admin@example.com)
	@echo "$(BLUE)[CERTS] Generating certificates...$(NC)"
	@bash $(SCRIPTS_DIR)/generate-certs.sh $(DEPLOY_DIR)/certs $(MODE) $(DOMAIN) $(EMAIL)

secrets: ## Generate production secrets (run once, store in secrets manager)
	@echo "$(BLUE)[SECRETS] Generating production secrets...$(NC)"
	@bash $(SCRIPTS_DIR)/generate-secrets.sh

# =============================================================================
# DEPLOYMENT
# =============================================================================

deploy-docker: ## Deploy using Docker Compose (ACTION=up|down|restart|logs|status|backup|restore PROFILE=monitoring|icap|monitor|all)
	@bash $(SCRIPTS_DIR)/deploy.sh docker $(ACTION) $(PROFILE)

deploy-k8s: ## Deploy to Kubernetes (ACTION=up|down|restart|logs|status|backup|restore)
	@bash $(SCRIPTS_DIR)/deploy.sh k8s $(ACTION)

deploy-systemd: ## Deploy as systemd services (ACTION=up|down|restart|logs|status) - requires root
	@bash $(SCRIPTS_DIR)/deploy.sh systemd $(ACTION)

# =============================================================================
# OPERATIONS
# =============================================================================

logs: ## Follow logs (SERVICE=backend|nginx|db|redis|icap|monitor|prometheus|grafana)
	@if [ -n "$(SERVICE)" ]; then \
		docker compose -f $(DOCKER_COMPOSE_FILE) logs -f --tail=100 $(SERVICE); \
	else \
		docker compose -f $(DOCKER_COMPOSE_FILE) logs -f --tail=100; \
	fi

status: ## Show service status
	@docker compose -f $(DOCKER_COMPOSE_FILE) ps

health: ## Run health checks on all services
	@echo "$(BLUE)[HEALTH] Checking service health...$(NC)"
	@for i in $$(seq 1 30); do \
		if curl -kfs https://localhost/api/health >/dev/null 2>&1; then \
			echo "$(GREEN)[HEALTH] API health check passed$(NC)"; \
			curl -ks https://localhost/api/health | jq .; \
			exit 0; \
		fi; \
		sleep 2; \
	done; \
	echo "$(RED)[HEALTH] Health check failed after 60 seconds$(NC)"; \
	exit 1

backup: ## Create full backup (database + storage + configs)
	@echo "$(BLUE)[BACKUP] Creating backup...$(NC)"
	@mkdir -p $(BACKUP_DIR)
	@TIMESTAMP=$$(date +%Y%m%d_%H%M%S); \
	docker compose -f $(DOCKER_COMPOSE_FILE) exec -T db pg_dump -U malinfo malinfo | gzip > $(BACKUP_DIR)/db_$$TIMESTAMP.sql.gz; \
	docker run --rm -v malinfo_storage:/data -v $(BACKUP_DIR):/backup alpine tar czf /backup/storage_$$TIMESTAMP.tar.gz -C /data .; \
	tar czf $(BACKUP_DIR)/malinfo_backup_$$TIMESTAMP.tar.gz -C $(PROJECT_ROOT) .env $(DOCKER_COMPOSE_FILE) $(DEPLOY_DIR)/; \
	echo "$(GREEN)[BACKUP] Backup completed: $(BACKUP_DIR)/malinfo_backup_$$TIMESTAMP.tar.gz$(NC)"

restore: ## Restore from backup (BACKUP_FILE=path/to/backup.tar.gz)
	@if [ -z "$(BACKUP_FILE)" ]; then \
		echo "$(RED)[ERROR] BACKUP_FILE required$(NC)"; \
		exit 1; \
	fi
	@echo "$(YELLOW)[WARN] This will overwrite current data. Continue? (y/N)$(NC)"; \
	read confirm; \
	if [ "$$confirm" = "y" ]; then \
		docker compose -f $(DOCKER_COMPOSE_FILE) down; \
		tar xzf $(BACKUP_FILE) -C $(PROJECT_ROOT); \
		DB_DUMP=$$(ls -t $(BACKUP_DIR)/db_*.sql.gz 2>/dev/null | head -1); \
		if [ -n "$$DB_DUMP" ]; then \
			docker compose -f $(DOCKER_COMPOSE_FILE) up -d db; \
			sleep 10; \
			gunzip -c $$DB_DUMP | docker compose -f $(DOCKER_COMPOSE_FILE) exec -T db psql -U malinfo malinfo; \
		fi; \
		STORAGE_BACKUP=$$(ls -t $(BACKUP_DIR)/storage_*.tar.gz 2>/dev/null | head -1); \
		if [ -n "$$STORAGE_BACKUP" ]; then \
			docker run --rm -v malinfo_storage:/data -v $$(dirname $$STORAGE_BACKUP):/backup alpine tar xzf /backup/$$(basename $$STORAGE_BACKUP) -C /data; \
		fi; \
		docker compose -f $(DOCKER_COMPOSE_FILE) up -d; \
		echo "$(GREEN)[RESTORE] Restore completed$(NC)"; \
	else \
		echo "Aborted."; \
	fi

update-yara: ## Update YARA rules from feeds
	@echo "$(BLUE)[YARA] Updating rules from feeds...$(NC)"
	@docker compose -f $(DOCKER_COMPOSE_FILE) exec backend python -m app.analysis.yara_manager sync_all_feeds
	@echo "$(GREEN)[YARA] Rules updated$(NC)"

update-feeds: ## Update threat intelligence feeds
	@echo "$(BLUE)[THREAT-INTEL] Updating feeds...$(NC)"
	@docker compose -f $(DOCKER_COMPOSE_FILE) exec backend python -m app.threat_intel.integration sync_all_feeds
	@echo "$(GREEN)[THREAT-INTEL] Feeds updated$(NC)"

generate-reports: ## Generate reports for all samples missing reports
	@echo "$(BLUE)[REPORTS] Generating missing reports...$(NC)"
	@docker compose -f $(DOCKER_COMPOSE_FILE) exec backend python -m app.reporting.report_generator generate_all
	@echo "$(GREEN)[REPORTS] Reports generated$(NC)"

# =============================================================================
# DEVELOPMENT
# =============================================================================

test: ## Run all tests
	@echo "$(BLUE)[TEST] Running tests...$(NC)"
	@cd $(BACKEND_DIR) && python -m pytest tests/ -v --tb=short

test-unit: ## Run unit tests only
	@cd $(BACKEND_DIR) && python -m pytest tests/unit -v

test-integration: ## Run integration tests
	@cd $(BACKEND_DIR) && python -m pytest tests/integration -v

lint: ## Run linting (ruff, mypy, bandit)
	@echo "$(BLUE)[LINT] Running linters...$(NC)"
	@cd $(BACKEND_DIR) && python -m ruff check .
	@cd $(BACKEND_DIR) && python -m mypy app/
	@cd $(BACKEND_DIR) && python -m bandit -r app/ -f json -o bandit-report.json || true

security: ## Run security scans
	@echo "$(BLUE)[SECURITY] Running security scans...$(NC)"
	@cd $(BACKEND_DIR) && python -m pip install safety && python -m safety check --json --output safety-report.json || true
	@cd $(BACKEND_DIR) && python -m pip install trivy && trivy fs --format json --output trivy-report.json . || true

sbom: ## Generate Software Bill of Materials (CycloneDX)
	@echo "$(BLUE)[SBOM] Generating SBOM...$(NC)"
	@cd $(BACKEND_DIR) && python -m pip install cyclonedx-bom && cyclonedx-py -o ../sbom-backend.json
	@cd $(PROJECT_ROOT) && syft packages dir:. -o cyclonedx-json=sbom-full.json || true
	@echo "$(GREEN)[SBOM] SBOM generated: sbom-backend.json, sbom-full.json$(NC)"

clean: ## Clean up build artifacts and caches
	@echo "$(BLUE)[CLEAN] Cleaning up...$(NC)"
	@find . -type d -name __pycache__ -exec rm -rf {} + 2>/dev/null || true
	@find . -type f -name "*.pyc" -delete 2>/dev/null || true
	@find . -type f -name "*.pyo" -delete 2>/dev/null || true
	@find . -type d -name ".pytest_cache" -exec rm -rf {} + 2>/dev/null || true
	@find . -type d -name ".mypy_cache" -exec rm -rf {} + 2>/dev/null || true
	@rm -rf $(BACKEND_DIR)/.coverage $(BACKEND_DIR)/htmlcov $(BACKEND_DIR)/bandit-report.json $(BACKEND_DIR)/safety-report.json $(BACKEND_DIR)/trivy-report.json 2>/dev/null || true
	@echo "$(GREEN)[CLEAN] Cleanup completed$(NC)"

# =============================================================================
# INTERNAL HELPERS
# =============================================================================

_check-env:
	@if [ ! -f $(ENV_FILE) ]; then \
		echo "$(RED)[ERROR] $(ENV_FILE) not found. Run 'make init' first.$(NC)"; \
		exit 1; \
	fi
	@if grep -q "CHANGE_ME" $(ENV_FILE); then \
		echo "$(YELLOW)[WARN] $(ENV_FILE) contains placeholder values. Update before production!$(NC)"; \
	fi

_check-env-prod: _check-env
	@if grep -q "CHANGE_ME" $(ENV_FILE); then \
		echo "$(RED)[ERROR] Production deployment requires all secrets configured in $(ENV_FILE)$(NC)"; \
		exit 1; \
	fi
	@if [ ! -f $(DEPLOY_DIR)/certs/fullchain.pem ] || [ ! -f $(DEPLOY_DIR)/certs/privkey.pem ]; then \
		echo "$(RED)[ERROR] TLS certificates not found. Run 'make certs MODE=letsencrypt DOMAIN=yourdomain.com EMAIL=admin@yourdomain.com'$(NC)"; \
		exit 1; \
	fi