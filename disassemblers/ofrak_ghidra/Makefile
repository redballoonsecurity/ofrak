PYTHON=python3
PIP=pip3

install:
	$(PIP) install .

develop:
	$(PIP) install -e . --config-settings editable_mode=compat

test:
	$(PYTHON) -m pytest --cov=ofrak_ghidra --cov-report=term-missing tests
	fun-coverage --cov-fail-under=100
