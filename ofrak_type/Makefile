PYTHON=python3
PIP=pip3

.PHONY: develop
install:
	$(PIP) install .

.PHONY: install
develop:
	$(PIP) install -e .[test]

.PHONY: inspect
inspect:
	mypy

.PHONY: test
test: inspect
	$(PYTHON) -m pytest -n auto --cov=ofrak_type --cov-report=term-missing --cov-fail-under=100 ofrak_type_test
	@if [ "$(shell uname -m)" = "x86_64" ]; then \
		fun-coverage --cov-fail-under=100; \
	else \
		fun-coverage; \
	fi
