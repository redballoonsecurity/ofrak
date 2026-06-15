PYTHON=python3

install:
	$(PYTHON) -m pip install .

develop:
	$(PYTHON) -m pip install -e . --config-settings editable_mode=compat

test:
	$(PYTHON) -m pytest --cov=ofrak_ghidra --cov-report=term-missing tests
	fun-coverage --cov-fail-under=100
