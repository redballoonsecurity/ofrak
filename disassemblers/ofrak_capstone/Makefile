PYTHON=python3
PIP=pip3

.PHONY: install
install:
	$(PIP) install --pre .

.PHONY: develop
develop:
	$(PIP) install --pre -e .[test] --config-settings editable_mode=compat

.PHONY: inspect
inspect:
	mypy

.PHONY: test
test: inspect
	$(PYTHON) -m pytest ofrak_capstone_test --cov=ofrak_capstone --cov-report=term-missing
	fun-coverage --cov-fail-under=100 || ! (shell uname -m | grep x86_64)
