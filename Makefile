# Makefile for Neptune Swift Package
# 
# This Makefile automates:
# 1. Managing the secp256k1 submodule
# 2. Generating Swift documentation for GitHub Pages
#
# Usage:
#   make check-secp256k1    - Verify submodule exists and is initialized (default target)
#   make update-secp256k1   - Update submodule to referenced commit
#   make pull-secp256k1     - Pull latest from secp256k1 remote
#   make init-secp256k1     - Initialize submodule if not already initialized
#   make docs               - Generate documentation for GitHub Pages
#   make generate-docs      - Generate documentation in docs/ directory
#   make clean-docs         - Remove generated documentation

# Paths
SECP256K1_DIR := Sources/CNeptune/secp256k1
SECP256K1_MAKEFILE := $(SECP256K1_DIR)/Makefile
SECP256K1_CMAKE := $(SECP256K1_DIR)/CMakeLists.txt

.PHONY: all check-secp256k1 update-secp256k1 pull-secp256k1 init-secp256k1 help docs generate-docs clean-docs

# Default target
all: check-secp256k1

# Documentation paths
DOCS_DIR := docs
DOCC_PLUGIN_URL := https://github.com/swiftlang/swift-docc-plugin
DOCC_PLUGIN_FROM := 1.1.0
PACKAGE_MANIFEST := Package.swift

help:
	@echo "Neptune Swift Package Makefile"
	@echo ""
	@echo "Targets:"
	@echo "  make check-secp256k1   - Verify submodule exists and is initialized (default)"
	@echo "  make init-secp256k1    - Initialize submodule if not already initialized"
	@echo "  make update-secp256k1  - Update submodule to referenced commit"
	@echo "  make pull-secp256k1    - Pull latest from secp256k1 remote, then update"
	@echo "  make docs              - Generate documentation for GitHub Pages"
	@echo "  make generate-docs     - Generate documentation in docs/ directory"
	@echo "  make clean-docs        - Remove generated documentation"
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

# Generate documentation using Swift-DocC Plugin.
# The plugin is added to Package.swift only for this target so downstream apps
# (Xcode/Tuist) never need to resolve swift-docc-plugin. See Swift Forums:
# https://forums.swift.org/t/how-do-i-build-html/81972
generate-docs:
	@echo "Generating Swift documentation..."
	@if ! command -v swift >/dev/null 2>&1; then \
		echo "❌ ERROR: Swift is not installed or not in PATH"; \
		exit 1; \
	fi
	@manifest_backup=$$(mktemp); \
	cp "$(PACKAGE_MANIFEST)" "$$manifest_backup"; \
	trap 'cp "$$manifest_backup" "$(PACKAGE_MANIFEST)"' EXIT; \
	if ! grep -q 'github.com/swiftlang/swift-docc-plugin' "$(PACKAGE_MANIFEST)"; then \
		echo "Adding swift-docc-plugin temporarily for documentation build..."; \
		swift package add-dependency "$(DOCC_PLUGIN_URL)" --from "$(DOCC_PLUGIN_FROM)"; \
	fi; \
	echo "Resolving package dependencies..."; \
	swift package resolve || (echo "❌ ERROR: Failed to resolve package dependencies"; exit 1); \
	echo "Building package..."; \
	swift build || (echo "❌ ERROR: Failed to build package"; exit 1); \
	echo "Generating documentation with static hosting transformation..."; \
	swift package --allow-writing-to-directory "$(DOCS_DIR)" \
		generate-documentation \
		--target Neptune \
		--output-path "$(DOCS_DIR)" \
		--transform-for-static-hosting \
		--hosting-base-path /Neptune || (echo "❌ ERROR: Failed to generate documentation"; exit 1); \
	echo "✓ Documentation generated in $(DOCS_DIR)/"
	@echo ""
	@echo "To publish on GitHub Pages:"
	@echo "  1. Commit the docs/ directory"
	@echo "  2. Go to Settings → Pages in your GitHub repository"
	@echo "  3. Select 'Deploy from a branch' → 'main' → '/docs'"
	@echo "  4. Your docs will be available at: https://bespalov-software.github.io/Neptune/"

# Alias for generate-docs
docs: generate-docs

# Clean generated documentation
clean-docs:
	@echo "Cleaning generated documentation..."
	@rm -rf $(DOCS_DIR)
	@rm -rf .build/documentation
	@echo "✓ Documentation cleaned"

