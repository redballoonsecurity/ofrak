PYTHON=python3
PIP=pip3

install:
	$(PIP) install .

develop:
	$(PIP) install -e .[test]

test:
	$(PYTHON) -m pytest --benchmark-skip --cov=ofrak_pyghidra --cov-report=term-missing tests
	fun-coverage --cov-fail-under=100
benchmark:
	$(PYTHON) -m pytest --benchmark-only --benchmark-json benchmark.json tests
