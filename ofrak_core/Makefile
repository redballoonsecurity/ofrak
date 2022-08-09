PYTHON=python3
PIP=pip3

.PHONY: install
install:
	$(PIP) install .

.PHONY: develop
develop:
	$(PIP) install -e .[docs,test]

.PHONY: inspect
inspect:
	mypy

.PHONY: test-core
test-core:
	$(PYTHON) -m pytest test_ofrak/unit test_ofrak/components --cov=ofrak --cov-report=term-missing
	fun-coverage

.PHONY: test-services
test-services:
	$(PYTHON) -m pytest test_ofrak/service --cov=ofrak --cov-report=term-missing
	fun-coverage

.PHONY: test
test: inspect test-core test-services

.PHONY: dependencies
dependencies:
