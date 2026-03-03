PYTHON=python3

.PHONY: install
install:
	$(PYTHON) -m pip install --pre .

.PHONY: develop
develop:
	$(PYTHON) -m pip install --pre -e . --config-settings editable_mode=compat

.PHONY: inspect
inspect:
	$(PYTHON) -m mypy

.PHONY: test
test: inspect
	$(PYTHON) -m pytest tests --cov=ofrak_capstone --cov-report=term-missing
	fun-coverage --cov-fail-under=100
