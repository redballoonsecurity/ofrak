PYTHON=python3
PIP=pip3

.PHONY: install
install:
	$(MAKE) -C ofrak_components/entropy
	$(PIP) install .

.PHONY: develop
develop:
	$(MAKE) -C ofrak_components/entropy
	$(PIP) install -e .[docs,test]

.PHONY: inspect
inspect:
	mypy

.PHONY: test-components
test-components:
	$(PYTHON) -m pytest ofrak_components_test --cov=ofrak_components --cov-report=term-missing
	fun-coverage

.PHONY: test
test: inspect test-components

.PHONY: dependencies
dependencies:
