PYTHON=python3
PIP=pip3

.PHONY: install
install:
	$(PIP) install --pre .

.PHONY: develop
develop:
	# Legacy-edinable is needed to allow mypy to find packages.
	# See https://github.com/python/mypy/issues/13392
	SETUPTOOLS_ENABLE_FEATURES="legacy-editable" $(PIP) install --pre -e .[test]

.PHONY: inspect
inspect:
	mypy

.PHONY: test
test: inspect
	$(PYTHON) -m pytest ofrak_capstone_test --cov=ofrak_capstone --cov-report=term-missing
	fun-coverage --cov-fail-under=100
