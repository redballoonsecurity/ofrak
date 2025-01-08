PYTHON=python3
PIP=pip3

install:
	$(PIP) install .

develop:
	$(PIP) install -e .[test]

test:
	$(PYTHON) -m pytest --cov=ofrak_cached --cov-report=term-missing ofrak_cached_test
	fun-coverage --cov-fail-under=100
