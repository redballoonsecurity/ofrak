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
	$(PYTHON) -m pytest --cov=ofrak_capstone --cov-report=term-missing test_ofrak_capstone.py
	fun-coverage --cov-fail-under=100

.PHONY: dependencies
dependencies:
