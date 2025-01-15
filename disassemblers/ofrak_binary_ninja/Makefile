PYTHON=python3
PIP=pip3

.PHONY: install
install:
	$(PIP) install .

.PHONY: develop
develop:
	# Legacy-edinable is needed to allow mypy to find packages.
	# See https://github.com/python/mypy/issues/13392
	SETUPTOOLS_ENABLE_FEATURES="legacy-editable" $(PIP) install -e .[test]

.PHONY: inspect
inspect:
	mypy

.PHONY: test
test: inspect
	$(PYTHON) -m pytest --cov=ofrak_binary_ninja --cov-report=term-missing ofrak_binary_ninja_test
	fun-coverage --cov-fail-under=100
