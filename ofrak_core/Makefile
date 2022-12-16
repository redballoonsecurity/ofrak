PYTHON=python3
PIP=pip3

.PHONY: install
install:
	$(MAKE) -C ofrak/core/entropy
	$(PIP) install .

.PHONY: develop
develop:
	$(PIP) install -e .[docs,test]

.PHONY: inspect
inspect:
	mypy

.PHONY: test
test: inspect
	$(PYTHON) -m pytest -n auto test_ofrak --cov=ofrak --cov-report=term-missing
	fun-coverage --cov-fail-under=96

.PHONY: dependencies
dependencies:
