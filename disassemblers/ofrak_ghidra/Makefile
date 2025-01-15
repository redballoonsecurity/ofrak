PYTHON=python3
PIP=pip3

install:
	$(PIP) install .

develop:
	# Legacy-edinable is needed to allow mypy to find packages.
	# See https://github.com/python/mypy/issues/13392
	SETUPTOOLS_ENABLE_FEATURES="legacy-editable" $(PIP) install -e .[test]

test:
	$(PYTHON) -m pytest --cov=ofrak_ghidra --cov-report=term-missing ofrak_ghidra_test
	fun-coverage --cov-fail-under=100
