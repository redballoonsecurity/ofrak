PYTHON=python3

install:
	$(PYTHON) -m pip install .

develop:
	$(PYTHON) -m pip install -e .[test]

test:
	$(PYTHON) -m pytest --cov=ofrak_pyghidra --cov-report=term-missing tests
	fun-coverage --cov-fail-under=100
