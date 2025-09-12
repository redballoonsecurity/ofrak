PYTHON=python3
PIP=pip3

install:
	$(PIP) install .

develop:
	$(PIP) install -e .

test:
	$(PYTHON) -m pytest --cov=ofrak_cached_disassembly --cov-report=term-missing ofrak_cached_disassembly_test
	fun-coverage --cov-fail-under=100
