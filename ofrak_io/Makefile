PYTHON=python3
PIP=pip3

.PHONY: install
install:
	$(PIP) install .

.PHONY: develop
develop:
	$(PIP) install -e .[test] --config-settings editable_mode=strict

.PHONY: inspect
inspect:
	mypy

.PHONY: test
test: inspect
	$(PYTHON) -m pytest -n auto --cov=ofrak_io --cov-report=term-missing --cov-fail-under=100 ofrak_io_test
	@if [ "$(shell uname -m)" = "x86_64" ]; then \
		fun-coverage --cov-fail-under=100; \
	else \
		fun-coverage; \
	fi
