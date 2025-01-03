.PHONY: check-black
check-black: ## Run black in check + diff mode
	black . --check --diff

.PHONY: autoflake
autoflake: ## Remove all unused imports recursively
	autoflake --in-place --remove-all-unused-imports --ignore-init-module-imports -r . -c

.PHONY: inspect
inspect: ## Runs autoflake then check-black
	autoflake
	make check-black

# For compatibility, this target calls the pattern rule for "ofrak-core-dev"
# so "make image" continues to work as before.
.PHONY: image
image: ofrak-core-dev ## Build ofrak-core-dev image

# For compatibility, this target calls the pattern rule for "ofrak-tutorial"
# so "make tutorial-image" continues to work as before.
.PHONY: tutorial-image
tutorial-image: ofrak-tutorial ## Build OFRAK tutorial Docker image

.PHONY: tutorial-run
tutorial-run: ## Run the tutorial inside ofrak_tutorial
	make -C ofrak_tutorial run

# ----------------------------------------------------------------------------
# Ensure OFRAK license is present
# ----------------------------------------------------------------------------

# We'll store the license locally in ofrak.license
license_file = $(PWD)/ofrak.license

.PHONY: ensure-ofrak-license
ensure-ofrak-license:
	@if [ ! -f "$(license_file)" ]; then \
		echo "No local 'ofrak.license' found."; \
		echo "Launching container to obtain license from IMAGE: 'redballoonsecurity/ofrak/$(image_name):latest'..."; \
		docker run --name ofrak-license-check \
			-it \
			--entrypoint '' \
			redballoonsecurity/ofrak/$(image_name):latest \
			ofrak license; \
		if [ "$$?" -eq 0 ]; then \
			echo "License accepted. Copying license file out of container..."; \
			docker cp ofrak-license-check:/ofrak_core/ofrak/license/license.json "$(license_file)"; \
		else \
			echo "License was NOT accepted or command failed. Exiting..."; \
			docker rm ofrak-license-check >/dev/null 2>&1 || true; \
			exit 1; \
		fi; \
		docker rm ofrak-license-check >/dev/null 2>&1 || true; \
	fi

# ----------------------------------------------------------------------------
# BUILD VARIOUS OFRAK IMAGES WITH A PATTERN RULE
# ----------------------------------------------------------------------------

# Pattern rule for building images named "ofrak-<name>".
# Usage examples:
#   make ofrak-dev         -> builds with ofrak-dev.yml
#   make ofrak-angr        -> builds with ofrak-angr.yml
#   make ofrak-binary-ninja-> builds with ofrak-binary-ninja.yml
#   make ofrak-core-dev    -> builds with ofrak-core-dev.yml
#   make ofrak-ghidra      -> builds with ofrak-ghidra.yml
#   make ofrak-tutorial    -> builds with ofrak-tutorial.yml
.PHONY: ofrak-%
ofrak-%: ## Build OFRAK image using ofrak-<name>
	@echo "Building OFRAK image using config: ofrak-$*.yml"
	python3 build_image.py --config ofrak-$*.yml --base --finish

# ----------------------------------------------------------------------------
# START VARIOUS OFRAK IMAGES WITH A PATTERN RULE
# ----------------------------------------------------------------------------

# Pattern rule for starting images named "ofrak-<name>".
# Usage examples:
#   make start-ofrak-dev         -> starts ofrak-dev image
#   make start-ofrak-angr        -> starts ofrak-angr image
#   make start-ofrak-binary-ninja-> starts ofrak-binary-ninja image
#   make start-ofrak-core-dev    -> starts ofrak-core-dev image
#   make start-ofrak-ghidra      -> starts ofrak-ghidra image
#   make start-ofrak-tutorial    -> starts ofrak-tutorial image
.PHONY: start-ofrak-%
start-ofrak-%: ## Start OFRAK image using ofrak-<name>
	make ensure-ofrak-license image_name=$*
	@echo "Starting OFRAK image using config: ofrak-$*.yml..."
	docker run \
	  --rm \
	  --detach \
	  --hostname ofrak \
	  --name ofrak-$* \
	  --interactive \
	  --tty \
	  --publish 8877:80 \
	  --volume $(pwd)/ofrak.license:/ofrak.license \
	  redballoonsecurity/ofrak/$*:latest

define check_for_binja_license
	$(shell python3 -c "import os; license_path = os.path.join(os.getcwd(), 'license.dat'); vol_args = f'--mount type=bind,source={license_path},target=/root/.binaryninja/license.dat' if os.path.isfile(license_path) else ''; print(vol_args)")
endef

# Yes this is actually how you input a newline in a makefile
define newline


endef

# Function to get package paths from YAML
# $(1) - config file path
# $(shell grep -A100 "packages_paths:" $(1) | grep -v "packages_paths:" | grep -B100 "extra_build_args\|$$" | grep "^[[:space:]]*-" | sed 's/[[:space:]]*-[[:space:]]*//')
define get_packages
$(shell grep -A100 "packages_paths:" ofrak-ghidra.yml | grep -v "packages_paths:" | grep -B100 "]" | sed -n 's/.*"\([^"]*\)".*/\1/p')
endef

# Function to generate volume mounts
# $(1) - list of packages
define volume_mounts
$(foreach pkg,$(1),--volume "$$(pwd)"/$(pkg):/$(shell basename $(pkg)) \$(newline))
endef

.PHONY: super-start-ofrak-%
super-start-ofrak-%: ## Start OFRAK image with mounted volumes, profiling tools, misc dev utils, and a modified entrypoint
	make ensure-ofrak-license image_name=$*
	@echo "Starting OFRAK "super" image using config: ofrak-$*.yml..."
	$(eval CONFIG_FILE := ofrak-$*.yml)
	$(eval PACKAGES := $(call get_packages,$(CONFIG_FILE)))
	docker run \
	  --rm \
	  --detach \
	  --hostname ofrak \
	  --name super-ofrak-$* \
	  --interactive \
	  --tty \
	  --publish 8877:80 \
	  --cap-add SYS_PTRACE \
	  $(call check_for_binja_license,) \
	  $(call volume_mounts,$(PACKAGES)) --entrypoint bash \
	  redballoonsecurity/ofrak/dev:latest \
	  -c 'make develop \
	  && ofrak license --community --i-agree \
	  && (sleep infinity)'

	@echo "Install common profiling packages (py-spy, yappi) and other utilities..."
	docker exec -it super-ofrak-$* bash -c "python3 -m pip install py-spy yappi"
	docker exec -it super-ofrak-$* bash -c "apt-get install -y vim nano less"

.PHONY: use-local-in-setup-py
use-local-in-setup-py: ## Back up and modify setup.py references to local OFRAK packages
	@echo "Backing up and modifying all setup.py files..."
	find . -name "setup.py" ! -name "*.bak" -exec sh -c '[ -f "{}.bak" ] || cp "{}" "{}.bak"' \;
	find . -name "setup.py" -exec sed -i -E 's/(ofrak_[A-Za-z0-9_]+)~=[0-9]+\.[0-9]+/\1 @ file:\/\/\/\1/g' {} \;
	@echo "Done. All setup.py references updated to local paths."

.PHONY: restore-setup-py
restore-setup-py: ## Restore setup.py from backups
	@echo "Restoring any setup.py from its backup..."
	find . -name "setup.py.bak" -exec sh -c 'f="{}"; mv "$$f" "$${f%.bak}"' \;
	@echo "Done. All setup.py files have been restored."

# ----------------------------------------------------------------------------
# TEST TARGETS SIMILAR TO THE GITHUB CI JOBS
# ----------------------------------------------------------------------------

.PHONY: test-ofrak-ghidra
test-ofrak-ghidra: IMAGE_NAME = redballoonsecurity/ofrak/ghidra:latest
test-ofrak-ghidra: ## Build the Ghidra Docker image and run documentation + main OFRAK tests
	@echo "=== Building the Ghidra image (similar to GH Actions) ==="
	python3 -m pip install --quiet PyYAML
	python3 build_image.py \
		--config ofrak-ghidra.yml \
		--base \
		--finish

	@echo "=== Testing documentation build in ofrak-ghidra ==="
	docker run \
		--interactive \
		--rm \
		--entrypoint bash \
		--volume "$(PWD)":/ofrak \
		redballoonsecurity/ofrak/ghidra:latest \
		-c "cd /ofrak && mkdocs build --site-dir /tmp/docs"

	@echo "=== Testing OFRAK components in ofrak-ghidra ==="
	docker run \
		--interactive \
		--rm \
		--entrypoint bash \
		redballoonsecurity/ofrak/ghidra:latest \
		-c "python -m ofrak_ghidra.server start \
		    && ofrak license --community --i-agree \
		    && make test"

.PHONY: test-ofrak-angr
test-ofrak-angr: IMAGE_NAME = redballoonsecurity/ofrak/angr:latest
test-ofrak-angr: ## Build the angr Docker image and run angr/capstone tests
	@echo "=== Building the angr image (similar to GH Actions) ==="
	python3 -m pip install --quiet PyYAML
	python3 build_image.py \
		--config ofrak-angr.yml \
		--base \
		--finish

	@echo "=== Testing OFRAK angr + capstone components ==="
	docker run \
		--interactive \
		--rm \
		--entrypoint bash \
		--volume "$(PWD)":/ofrak \
		redballoonsecurity/ofrak/angr:latest \
		-c "ofrak license --community --i-agree \
		    && make -C /ofrak_angr test \
		    && make -C /ofrak_capstone test"

.PHONY: test-ofrak-tutorial
test-ofrak-tutorial: IMAGE_NAME = redballoonsecurity/ofrak/tutorial:latest
test-ofrak-tutorial: ## Build the tutorial Docker image and run the examples + tutorial tests
	@echo "=== Building the tutorial image (similar to GH Actions) ==="
	python3 -m pip install --quiet PyYAML
	python3 build_image.py \
		--config ofrak-tutorial.yml \
		--base \
		--finish

	@echo "=== Testing OFRAK tutorial notebooks and examples ==="
	docker run \
		--interactive \
		--rm \
		--entrypoint bash \
		redballoonsecurity/ofrak/tutorial:latest \
		-c "python -m ofrak_ghidra.server start \
		    && ofrak license --community --i-agree \
		    && make -C /examples test \
		    && make -C /ofrak_tutorial test"

.PHONY: test-all
test-all: test-ofrak-ghidra test-ofrak-angr test-ofrak-tutorial ## Run all tests (Ghidra, angr, tutorial)
	@echo "=== All tests completed! ==="

.PHONY: help
help: ## Display this help message.
	@echo "Usage: make [target]"
	@echo ""
	@echo "Targets:"
	@echo ""
	@awk 'BEGIN {FS = ":.*?## "} /^[a-zA-Z_%-]+:.*?## / {printf "  %-25s %s\n", $$1, $$2}' $(MAKEFILE_LIST)
