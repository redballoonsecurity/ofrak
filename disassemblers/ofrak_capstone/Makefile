PYTHON=python3
PIP=pip3

.PHONY: install
install:
	$(PIP) install --pre .

.PHONY: develop
develop:
	$(PIP) install --pre -e . --config-settings editable_mode=compat

.PHONY: inspect
inspect:
	mypy

.PHONY: test
test: inspect
	$(PYTHON) -m pytest tests --cov=ofrak_capstone --cov-report=term-missing
	fun-coverage --cov-fail-under=100
