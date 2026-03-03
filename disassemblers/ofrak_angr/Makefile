PYTHON=python3

.PHONY: install
install:
	$(PYTHON) -m pip install .

.PHONY: develop
develop:
	$(PYTHON) -m pip install -e . --config-settings editable_mode=compat

.PHONY: inspect
inspect:
	$(PYTHON) -m mypy

.PHONY: test
test: inspect
	$(PYTHON) -m pytest -n auto --cov=ofrak_angr tests
	fun-coverage --cov-fail-under=100
