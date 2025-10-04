PYTHON=python3
PIP=pip3

.PHONY: check-black
check-black:
	black . --check --diff

.PHONY: autoflake
autoflake:
	autoflake --in-place --remove-all-unused-imports --ignore-init-module-imports -r . -c

.PHONY: inspect
inspect: autoflake check-black

.PHONY: requirements-pip
requirements-pip:
	$(PYTHON) -m pip install -r requirements-pip.txt

.PHONY: requirements-dev
requirements-dev: requirements-pip
	$(PYTHON) -m pip install -r requirements-dev.txt

.PHONY: requirements-build
requirements-build: requirements-pip
	$(PYTHON) -m pip install -r requirements-build.txt

.PHONY: requirements-build-docker
requirements-build-docker: requirements-pip
	$(PYTHON) -m pip install -r requirements-build-docker.txt

.PHONY: develop
develop: develop-core
	@echo "Optional packages..."
	-$(MAKE) -C disassemblers/ofrak_angr develop
	-$(MAKE) -C disassemblers/ofrak_capstone develop
	-$(MAKE) -C disassemblers/ofrak_ghidra develop
	-$(MAKE) -C disassemblers/ofrak_pyghidra develop
	-$(MAKE) -C disassemblers/ofrak_cached_disassembly develop
	-$(MAKE) -C frontend develop
	-$(MAKE) -C ofrak_tutorial develop
	@echo "Development installation complete!"
	@echo "Run 'ofrak list' to verify installation"

.PHONY: develop-core
develop-core: requirements-pip requirements-dev
	@echo "Installing OFRAK core packages only..."
	$(MAKE) -C ofrak_type develop
	$(MAKE) -C ofrak_io develop
	$(MAKE) -C ofrak_patch_maker develop
	$(MAKE) -C ofrak_core develop
	$(MAKE) -C pytest_ofrak develop
	@echo "Core packages installed!"

tutorial-image:
	$(PYTHON) build_image.py --config ofrak-tutorial.yml --base --finish

tutorial-run:
	make -C ofrak_tutorial run
