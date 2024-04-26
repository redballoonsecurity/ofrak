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
	$(PYTHON) -m mypy

.PHONY: test
test: inspect
	$(PYTHON) -m pytest -n auto --cov=ofrak_angr ofrak_angr_test
	fun-coverage --cov-fail-under=100
