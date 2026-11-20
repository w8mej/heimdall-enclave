# Makefile — Unified Entrypoints for MCPMac Enterprise Fleet Deployment (FS-706 / D-R1)
.PHONY: deploy-L1 deploy-L2 deploy-L3 preflight verify clean-deployment

PROFILE ?= L1
CLI ?= $(shell if [ -x /opt/enterprise/enclave/bin/mcp-enclave ]; then echo /opt/enterprise/enclave/bin/mcp-enclave; elif [ -x ./target/release/mcp-enclave ]; then echo ./target/release/mcp-enclave; elif [ -x ./.enclave-local/dist/bin/mcp-enclave ]; then echo ./.enclave-local/dist/bin/mcp-enclave; else echo mcp-enclave; fi)
SUDO ?= $(shell if [ "$$(id -u)" -ne 0 ]; then echo "sudo"; fi)

BUILD_IF_NEEDED = @if [ ! -f .enclave-local/dist/codesign-pins.json ]; then \
	if [ "$$(id -u)" -eq 0 ] && [ -n "$$SUDO_USER" ]; then \
		sudo -u "$$SUDO_USER" sh packaging/macos/build.sh; \
	elif [ "$$(id -u)" -eq 0 ]; then \
		echo "build.sh: dist missing and no SUDO_USER; please run 'sh packaging/macos/build.sh' as normal user first" >&2; exit 1; \
	else \
		sh packaging/macos/build.sh; \
	fi; \
fi

deploy-L1:
	@echo "==> Deploying MCPMac Enclave (Profile L1: Startup / Direct R2)..."
	$(BUILD_IF_NEEDED)
	$(SUDO) $(CLI) deploy install --profile L1 --dist .enclave-local/dist
	$(SUDO) $(CLI) deploy verify --profile L1

deploy-L2:
	@echo "==> Deploying MCPMac Enclave (Profile L2: Growth / LAN Swarm)..."
	$(BUILD_IF_NEEDED)
	$(SUDO) $(CLI) deploy install --profile L2 --dist .enclave-local/dist
	$(SUDO) $(CLI) deploy verify --profile L2

deploy-L3:
	@echo "==> Deploying MCPMac Enclave (Profile L3: Enterprise MDM)..."
	$(BUILD_IF_NEEDED)
	$(SUDO) $(CLI) deploy install --profile L3 --dist .enclave-local/dist
	$(SUDO) $(CLI) deploy verify --profile L3

preflight:
	$(CLI) deploy preflight --profile $(PROFILE)

verify:
	$(SUDO) $(CLI) deploy verify --profile $(PROFILE)

clean-deployment:
	$(SUDO) $(CLI) deploy purge --profile $(PROFILE) --yes
