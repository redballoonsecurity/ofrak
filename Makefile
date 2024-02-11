.PHONY: check-black
check-black:
	black . --check --diff

.PHONY: autoflake
autoflake:
	autoflake --in-place --remove-all-unused-imports --ignore-init-module-imports -r . -c

.PHONY: inspect
inspect: autoflake check-black

.PHONY: image
image:
	python3 build_image.py --config ofrak-core-dev.yml --base --finish

tutorial-image:
	DOCKER_BUILDKIT=1 python3 build_image.py --config ofrak-tutorial.yml --base --finish

tutorial-run:
	make -C ofrak_tutorial run

OFRAK_INSTALL_PYTHON=python3

.PHONY: install_tutorial install_core install_develop install_test_all
install_tutorial:
	$(OFRAK_INSTALL_PYTHON) -m pip install pyyaml
	$(OFRAK_INSTALL_PYTHON) install.py --config ofrak-tutorial.yml --target install

install_core:
	$(OFRAK_INSTALL_PYTHON) -m pip install pyyaml
	$(OFRAK_INSTALL_PYTHON) install.py --config ofrak-core-dev.yml --target install

install_develop:
	$(OFRAK_INSTALL_PYTHON) -m pip install pyyaml
	$(OFRAK_INSTALL_PYTHON) install.py --config ofrak-dev.yml --target develop

install_test_all:
	$(OFRAK_INSTALL_PYTHON) -m pip install pyyaml
	$(OFRAK_INSTALL_PYTHON) install.py --config ofrak-all.yml --target develop --test
