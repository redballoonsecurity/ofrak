PYTHON=python3
PIP=pip3

.PHONY: install
install:
	$(PIP) install .

.PHONY: develop
develop:
	$(PIP) install -e .[test]

.PHONY: inspect
inspect:
	mypy

.PHONY: test
test: inspect
	$(PYTHON) -m pytest --cov=ofrak_binary_ninja --cov-report=term-missing ofrak_binary_ninja_test
	fun-coverage --cov-fail-under=87

.PHONY: dependencies
dependencies:
	test -f license.dat
	chmod +x ./install_binary_ninja_headless_linux.sh
