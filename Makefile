# Makefile for certboy project
#
# Usage:
#   make build          # Build release binary
#   make test           # Run tests with coverage
#   make bump           # Bump dev version (default)
#   make release       # Create formal release (with confirmation)
#   make help          # Show all targets

# =============================================================================
# Configuration
# =============================================================================

.PREFIX ?= /usr/local
BINDIR ?= $(PREFIX)/bin
AUDIT_DB_DIR ?= target/advisory-db
BUMP_TYPE ?= build

CURRENT_VERSION := $(shell cat VERSION 2>/dev/null || echo "unknown")
DEV_SUFFIX := $(shell echo $(CURRENT_VERSION) | grep -E '\-dev\.[0-9]+')

# Bumpver args based on bump type
ifeq ($(BUMP_TYPE),build)
  ifeq ($(strip $(DEV_SUFFIX)),)
    BUMP_ARGS := --patch --tag=dev
  else
    BUMP_ARGS := --tag-num
  endif
else ifeq ($(BUMP_TYPE),patch)
  BUMP_ARGS := --patch --tag=final
else
  $(error Invalid BUMP_TYPE '$(BUMP_TYPE)'. Use patch|build)
endif

# =============================================================================
# Build
# =============================================================================

.PHONY: all build build-release
all: build ## Default target

build: ## Build release binary
	cargo build --release --locked

build-release: ## Build release binary (alias)
	cargo build --release --locked

# =============================================================================
# Development
# =============================================================================

.PHONY: test clippy audit coverage check clean
test: ## Run tests with coverage (same as CI)
	@echo "=== Checking test dependencies ==="
	@if ! command -v cargo-nextest >/dev/null 2>&1; then \
		echo "cargo-nextest is not installed; installing..."; \
		cargo install cargo-nextest --locked; \
	fi
	@if ! command -v cargo-llvm-cov >/dev/null 2>&1; then \
		echo "cargo-llvm-cov is not installed; installing..."; \
		cargo install cargo-llvm-cov --locked; \
	fi
	@echo "=== Running tests with nextest and coverage ==="
	cargo llvm-cov nextest --profile ci --test-threads=1
	cargo llvm-cov report --cobertura --output-path target/llvm-cov-target/cobertura.xml
	cargo llvm-cov report --html --output-dir target/html

clippy: ## Run clippy linter (same as CI)
	cargo clippy --all-targets -- -D warnings

audit: ## Run cargo-audit (dependency vulnerability scan)
	@if ! command -v cargo-audit >/dev/null 2>&1; then \
		echo "cargo-audit is not installed; installing..."; \
		cargo install cargo-audit --locked; \
	fi
	@if [ -d "$(AUDIT_DB_DIR)/.git" ]; then \
		git -C "$(AUDIT_DB_DIR)" pull --ff-only || echo "Warning: failed to update advisory db; using cached copy"; \
	else \
		git clone --depth 1 https://github.com/RustSec/advisory-db.git "$(AUDIT_DB_DIR)"; \
	fi
	cargo audit --db "$(AUDIT_DB_DIR)" --no-fetch

coverage: test ## Alias for test

check: ## Run cargo check
	cargo check

clean: ## Clean build artifacts
	cargo clean

# =============================================================================
# Version Management
# =============================================================================

.PHONY: bump release check-deps

check-deps:
	@command -v bumpver >/dev/null 2>&1 || { echo >&2 "bumpver is not installed. Aborting."; exit 1; }
	@if [ "$(BUMP_TYPE)" = "patch" ]; then \
		command -v git-cliff >/dev/null 2>&1 || { echo >&2 "git-cliff is not installed. Aborting."; exit 1; }; \
	fi

bump: check-deps ## Bump dev version (default: build bump; use BUMP_TYPE=patch for release bump)
	@NEXT_VERSION="$$(bumpver update --dry $(BUMP_ARGS) 2>&1 | grep "New Version:" | awk '{print $$NF}')" ; \
	if [ -z "$$NEXT_VERSION" ]; then \
		echo "Error: Could not calculate next version. Check bumpver args."; \
		exit 1; \
	fi ; \
	echo "Current version: $(CURRENT_VERSION)" ; \
	echo "New version: v$$NEXT_VERSION" ; \
	if [ "$(BUMP_TYPE)" = "patch" ]; then \
		git-cliff --tag "v$$NEXT_VERSION" -o CHANGELOG.md ; \
		git add CHANGELOG.md Cargo.toml VERSION bumpver.toml ; \
	fi ; \
	bumpver update $(BUMP_ARGS) --allow-dirty --no-push ; \
	cargo check ; \
	if [ "$(BUMP_TYPE)" = "patch" ]; then \
		git add Cargo.lock ; \
		git commit --amend --no-edit ; \
		echo "Version bumped to v$$NEXT_VERSION and CHANGELOG.md updated." ; \
	else \
		echo "Version bumped to v$$NEXT_VERSION" ; \
	fi

release: check-deps ## Create formal release (prompts for confirmation)
	@NEXT_VERSION="$$(bumpver update --dry --patch --tag=final 2>&1 | grep "New Version:" | awk '{print $$NF}')" ; \
	if [ -z "$$NEXT_VERSION" ]; then \
		echo "Error: Could not calculate next version."; \
		exit 1; \
	fi ; \
	echo "" ; \
	echo "Current version: $(CURRENT_VERSION)" ; \
	echo "Ready to release: v$$NEXT_VERSION" ; \
	echo "" ; \
	read -p "Proceed with release v$$NEXT_VERSION? (y/n) " -n 1 -r; \
	echo ""; \
	if [[ ! $$REPLY =~ ^[Yy]$$ ]]; then \
		echo "Release aborted."; \
		exit 1; \
	fi; \
	git-cliff --tag "v$$NEXT_VERSION" -o CHANGELOG.md ; \
	bumpver update --patch --tag=final --allow-dirty --no-push ; \
	cargo check ; \
	git add CHANGELOG.md Cargo.toml VERSION bumpver.toml Cargo.lock ; \
	git commit --amend --no-edit ; \
	echo "" ; \
	echo "Release v$$NEXT_VERSION ready. Push to trigger CI."

# =============================================================================
# Installation
# =============================================================================

.PHONY: install musl musl-setup install-musl

install: ## Install via cargo
	cargo install --path . --force

musl-setup: ## Setup musl target
	rustup target add x86_64-unknown-linux-musl

musl: musl-setup ## Build static musl binary
	cargo build --release --locked --target x86_64-unknown-linux-musl

install-musl: musl ## Install musl binary
	install -Dm755 target/x86_64-unknown-linux-musl/release/certboy $(DESTDIR)$(BINDIR)/certboy

# =============================================================================
# Documentation
# =============================================================================

.PHONY: changelog doc-dev

changelog: ## Generate CHANGELOG.md
	git-cliff -o CHANGELOG.md

doc-dev: ## Serve documentation with live reload
	zensical serve

# =============================================================================
# Help
# =============================================================================

.PHONY: help
help: ## Show this help
	@grep -E '^[a-zA-Z0-9_-]+:.*?## .*$$' $(MAKEFILE_LIST) | sort | awk 'BEGIN {FS = ":.*?## "}; {printf "\033[36m%-20s\033[0m %s\n", $$1, $$2}'
