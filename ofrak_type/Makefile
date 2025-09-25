PYTHON=python3
PIP=pip3

.PHONY: install
install:
	$(PIP) install .

.PHONY: develop
develop:
	$(PIP) install -e . --config-settings editable_mode=compat

.PHONY: inspect
inspect:
	mypy

.PHONY: test
test: inspect
	$(PYTHON) -m pytest -n auto --cov=ofrak_type --cov-report=term-missing --cov-fail-under=100 tests
	fun-coverage --cov-fail-under=100
