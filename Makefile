# Makefile for managing secp256k1 submodule
# 
# This Makefile automates the process of:
# 1. Initializing and updating the secp256k1 submodule
# 2. Pulling latest changes from the secp256k1 remote
# 3. Verifying submodule setup
#
# Usage:
#   make check-secp256k1    - Verify submodule exists and is initialized (default target)
#   make update-secp256k1    - Update submodule to referenced commit
#   make pull-secp256k1     - Pull latest from secp256k1 remote
#   make init-secp256k1     - Initialize submodule if not already initialized

# Paths
SECP256K1_DIR := Sources/CNeptune/secp256k1
SECP256K1_MAKEFILE := $(SECP256K1_DIR)/Makefile
SECP256K1_CMAKE := $(SECP256K1_DIR)/CMakeLists.txt

.PHONY: all check-secp256k1 update-secp256k1 pull-secp256k1 init-secp256k1 help

# Default target
all: check-secp256k1

help:
	@echo "secp256k1 Submodule Management Makefile"
	@echo ""
	@echo "Targets:"
	@echo "  make check-secp256k1   - Verify submodule exists and is initialized (default)"
	@echo "  make init-secp256k1    - Initialize submodule if not already initialized"
	@echo "  make update-secp256k1  - Update submodule to referenced commit"
	@echo "  make pull-secp256k1    - Pull latest from secp256k1 remote, then update"
	@echo ""

# Verify secp256k1 submodule exists and is properly initialized
check-secp256k1:
	@echo "Checking secp256k1 submodule..."
	@if [ ! -d $(SECP256K1_DIR) ]; then \
		echo "❌ ERROR: secp256k1 submodule not found at $(SECP256K1_DIR)"; \
		echo "   Run: git submodule update --init --recursive"; \
		exit 1; \
	fi
	@if [ ! -f $(SECP256K1_CMAKE) ] && [ ! -f $(SECP256K1_MAKEFILE) ]; then \
		echo "❌ ERROR: secp256k1 submodule appears to be empty"; \
		echo "   Run: git submodule update --init --recursive"; \
		exit 1; \
	fi
	@if [ ! -d $(SECP256K1_DIR)/.git ]; then \
		echo "⚠️  WARNING: secp256k1 submodule may not be properly initialized"; \
		echo "   Run: git submodule update --init --recursive"; \
	else \
		echo "✓ secp256k1 submodule is properly initialized"; \
	fi

# Initialize secp256k1 submodule if not already initialized
init-secp256k1:
	@echo "Initializing secp256k1 submodule..."
	@if [ ! -d $(SECP256K1_DIR) ] || [ ! -f $(SECP256K1_CMAKE) ] && [ ! -f $(SECP256K1_MAKEFILE) ]; then \
		echo "Initializing submodule..."; \
		git submodule update --init --recursive $(SECP256K1_DIR); \
		echo "✓ Submodule initialized"; \
	else \
		echo "✓ Submodule already initialized"; \
	fi

# Update secp256k1 submodule to the commit referenced by parent repo
update-secp256k1: init-secp256k1
	@echo "Updating secp256k1 submodule to referenced commit..."
	@git submodule update --init --recursive $(SECP256K1_DIR)
	@echo "✓ Submodule updated to referenced commit"
	@$(MAKE) check-secp256k1

# Pull latest changes from secp256k1 remote, then update
pull-secp256k1: init-secp256k1
	@echo "Pulling latest secp256k1 from remote..."
	@if [ ! -d $(SECP256K1_DIR) ]; then \
		echo "Initializing secp256k1 submodule..."; \
		git submodule update --init --recursive $(SECP256K1_DIR); \
	fi
	@cd $(SECP256K1_DIR) && \
		BRANCH=$$(git rev-parse --abbrev-ref HEAD 2>/dev/null || echo "master"); \
		echo "Current branch: $$BRANCH"; \
		git fetch origin && \
		git pull origin $$BRANCH || echo "Note: Submodule may be on a specific commit, not a branch"
	@echo "✓ secp256k1 pulled from remote"
	@echo "⚠️  Note: You may need to commit the submodule update in the parent repository"
	@$(MAKE) check-secp256k1

