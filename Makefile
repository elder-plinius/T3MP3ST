# T3MP3ST — Makefile
# Run from the T3MP3ST/ directory.
#
#   make              → help
#   make quickstart   → full first-run setup
#   make build up     → rebuild and start

COMPOSE   := docker compose
CONTAINER := tempest-stack

.PHONY: help quickstart build up down restart logs shell test health clean \
        build-nocache rebuild status t3mp3st-logs

# ── Default target ────────────────────────────────────────────────────────────
help:
	@echo ""
	@echo "  T3MP3ST — available targets"
	@echo "  ──────────────────────────────────────────────────────"
	@echo "  make quickstart     First-time setup: env + build + start + test"
	@echo ""
	@echo "  make build          Build the Docker image"
	@echo "  make build-nocache  Build from scratch (no layer cache)"
	@echo "  make up             Start the stack (background)"
	@echo "  make down           Stop the stack"
	@echo "  make restart        Restart the stack"
	@echo "  make rebuild        build + up"
	@echo ""
	@echo "  make logs           Tail all container logs"
	@echo "  make t3mp3st-logs   Tail T3MP3ST service logs only"
	@echo "  make status         Show container and supervisor status"
	@echo "  make health         Curl the health + preflight endpoints"
	@echo ""
	@echo "  make test           Run the smoke suite inside the container"
	@echo "  make shell          Open a bash shell inside the container"
	@echo ""
	@echo "  make clean          Stop + remove volumes (destroys all mission data)"
	@echo ""

# ── First-run ─────────────────────────────────────────────────────────────────
quickstart:
	@bash quickstart.sh

# ── Build ─────────────────────────────────────────────────────────────────────
build:
	@echo "▸ Building..."
	$(COMPOSE) build

build-nocache:
	@echo "▸ Building from scratch..."
	$(COMPOSE) build --no-cache

# ── Lifecycle ─────────────────────────────────────────────────────────────────
up:
	@mkdir -p $(HOME)/.claude $(HOME)/.codex $(HOME)/.hermes
	$(COMPOSE) up -d
	@echo ""
	@echo "  Stack started. Waiting for health..."
	@for i in 1 2 3 4 5 6 7 8 9 10 11 12 13 14 15 16 17 18 19 20; do \
	  if curl -sfk --max-time 3 "https://localhost:$${TEMPEST_HTTPS_PORT:-8443}/health" >/dev/null 2>&1; then \
	    echo "  ✓ Ready → https://localhost:$${TEMPEST_HTTPS_PORT:-8443}  (run 'make logs' for password)"; break; \
	  fi; \
	  printf "."; sleep 3; \
	done; echo ""

down:
	$(COMPOSE) down

restart:
	$(COMPOSE) restart

rebuild: build up

# ── Observability ─────────────────────────────────────────────────────────────
logs:
	$(COMPOSE) logs -f

t3mp3st-logs:
	docker exec $(CONTAINER) supervisorctl tail -f t3mp3st

status:
	@echo "── Docker ─────────────────────────────────────────────"
	@$(COMPOSE) ps
	@echo ""
	@echo "── Supervisor processes ───────────────────────────────"
	@docker exec $(CONTAINER) supervisorctl status 2>/dev/null || echo "  (container not running)"

health:
	@echo "── T3MP3ST (internal) ─────────────────────────────────"
	@docker exec $(CONTAINER) curl -sf http://localhost:3333/health | python3 -m json.tool 2>/dev/null || echo "  not reachable"
	@echo ""
	@echo "── HTTPS proxy (nginx) ────────────────────────────────"
	@curl -sfk "https://localhost:$${TEMPEST_HTTPS_PORT:-8443}/health" | python3 -m json.tool 2>/dev/null || echo "  not reachable"
	@echo ""
	@echo "── Preflight (internal) ───────────────────────────────"
	@docker exec $(CONTAINER) curl -sf http://localhost:3333/api/preflight | python3 -m json.tool 2>/dev/null || echo "  not reachable"

# ── Testing ───────────────────────────────────────────────────────────────────
test:
	@echo "▸ Running smoke suite..."
	@docker exec $(CONTAINER) /opt/t3mp3st/scripts/test-container.sh

# ── Shell ─────────────────────────────────────────────────────────────────────
shell:
	docker exec -it $(CONTAINER) bash

# ── Clean ─────────────────────────────────────────────────────────────────────
clean:
	@echo "WARNING: This will delete all mission data and volumes."
	@echo "Press Ctrl-C to cancel, or wait 5 seconds..."
	@sleep 5
	$(COMPOSE) down -v
