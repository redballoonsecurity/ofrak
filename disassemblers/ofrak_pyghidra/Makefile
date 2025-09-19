PYTHON=python3
PIP=pip3

install:
	$(PIP) install .

develop:
	$(PIP) install -e .[test]

test:
	$(PYTHON) -m pytest --cov=ofrak_pyghidra --cov-report=term-missing tests
	fun-coverage --cov-fail-under=100
