# Makefile for certboy project

.PREFIX ?= /usr/local
BINDIR ?= $(PREFIX)/bin

.PHONY: all build check clean bump help check-deps test coverage clippy audit
.PHONY: release install musl musl-setup install-musl changelog

.PHONY: all build check clean bump help check-deps test
.PHONY: release install musl musl-setup install-musl changelog coverage

help: ## Show this help
	@grep -E '^[a-zA-Z0-9_-]+:.*?## .*$$' $(MAKEFILE_LIST) | sort | awk 'BEGIN {FS = ":.*?## "}; {printf "\033[36m%-20s\033[0m %s\n", $$1, $$2}'

test: ## Run tests with coverage (same as CI)
	@echo "=== Running tests with nextest and coverage ==="
	cargo llvm-cov nextest --profile ci --test-threads=1
	cargo llvm-cov report --cobertura --output-path target/llvm-cov-target/cobertura.xml
	cargo llvm-cov report --html --output-dir target/html

clippy: ## Run clippy (same as CI)
	cargo clippy --all-targets -- -D warnings

audit: ## Run cargo-audit (dependency vulnerability scan)
	@command -v cargo-audit >/dev/null 2>&1 || { echo >&2 "cargo-audit is not installed. Run: cargo install cargo-audit"; exit 1; }
	cargo audit

coverage: test ## Alias for test

all: build ## Build the project

build: ## Build the project using cargo
	cargo build

release:
	cargo build --release

check: ## Check the project using cargo
	cargo check

clean: ## Clean the project
	cargo clean

changelog: ## Generate CHANGELOG.md using git-cliff
	git-cliff -o CHANGELOG.md

install: ## Install the project using cargo
	cargo install --path . --force

musl-setup:
	rustup target add x86_64-unknown-linux-musl

musl: musl-setup
	cargo build --release --target x86_64-unknown-linux-musl

install-musl: musl
	install -Dm755 target/x86_64-unknown-linux-musl/release/certboy $(DESTDIR)$(BINDIR)/certboy

check-deps:
	@command -v bumpver >/dev/null 2>&1 || { echo >&2 "bumpver is not installed. Aborting."; exit 1; }
	@command -v git-cliff >/dev/null 2>&1 || { echo >&2 "git-cliff is not installed. Aborting."; exit 1; }

VERSION ?= build
CURRENT_VERSION := $(shell cat VERSION 2>/dev/null || echo "unknown")

DEV_SUFFIX := $(shell echo $(CURRENT_VERSION) | grep -E '\-dev\.[0-9]+')
ifeq ($(VERSION),build)
  ifeq ($(strip $(DEV_SUFFIX)),)
    BUMP_ARGS := --patch --tag=dev
  else
    BUMP_ARGS := --tag-num
  endif
else ifeq ($(VERSION),patch)
  BUMP_ARGS := --patch --tag=final
else
  $(error Invalid VERSION '$(VERSION)'. Use patch|build)
endif

NEXT_VERSION := $(shell bumpver update --dry $(BUMP_ARGS) 2>&1 | grep "New Version:" | awk '{print $$NF}')

bump: check-deps ## Bump version. Usage: make bump VERSION=patch|build (default: build)
	@if [ -z "$(NEXT_VERSION)" ]; then \
		echo "Error: Could not calculate next version. Check bumpver args."; \
		exit 1; \
	fi
	@echo "Current version: $(CURRENT_VERSION)"
	@echo "New version: v$(NEXT_VERSION)"
	@git-cliff --tag v$(NEXT_VERSION) -o CHANGELOG.md
	@git add CHANGELOG.md Cargo.toml VERSION bumpver.toml
	@bumpver update $(BUMP_ARGS) --allow-dirty --no-push
	@cargo check
	@git add Cargo.lock
	@git commit --amend --no-edit
	@git tag -a v$(NEXT_VERSION) -m "v$(NEXT_VERSION)"
	@echo "Version bumped to v$(NEXT_VERSION) and CHANGELOG.md updated."
	@echo "Don't forget to push: git push && git push --tags"
