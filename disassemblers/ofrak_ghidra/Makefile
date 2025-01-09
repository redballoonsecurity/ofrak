PYTHON=python3
PIP=pip3

install:
	$(PIP) install .

develop:
	$(PIP) install -e .[test]

test:
	$(PYTHON) -m pytest --cov=ofrak_ghidra --cov-report=term-missing ofrak_ghidra_test
	fun-coverage --cov-fail-under=100 || ! (shell uname -m | grep x86_64)
