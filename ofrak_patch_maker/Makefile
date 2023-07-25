PYTHON=python3
PIP=pip3


.PHONY: install
install:
	$(PIP) install .

.PHONY: develop
develop:
	$(PIP) install -e .[test]

.PHONY: inspect
inspect:
	mypy

.PHONY: test
test: inspect
	$(PYTHON) -m pytest -n auto --cov=ofrak_patch_maker --cov-report=term-missing ofrak_patch_maker_test
	fun-coverage --cov-fail-under=100
