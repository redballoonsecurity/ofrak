PYTHON=python3

.PHONY: install
install:
	$(PYTHON) -m pip install .

.PHONY: develop
develop:
	$(PYTHON) -m pip install -e .

.PHONY: inspect
inspect:
	$(PYTHON) -m mypy

.PHONY: test
test: inspect
	$(PYTHON) -m pytest --cov=ofrak_cached_disassembly --cov-report=term-missing tests
	fun-coverage --cov-fail-under=100
