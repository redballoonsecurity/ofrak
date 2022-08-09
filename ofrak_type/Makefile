PYTHON=python3
PIP=pip3

.PHONY: develop
install:
	$(PIP) install .

.PHONY: install
develop:
	$(PIP) install -e .[test]

.PHONY: inspect
inspect:
	mypy

.PHONY: test
test: inspect
	$(PYTHON) -m pytest --cov=ofrak_type --cov-report=term-missing --cov-fail-under=100 ofrak_type_test
	fun-coverage --cov-fail-under=100

.PHONY: dependencies
dependencies: ;

.PHONY: clean
clean: ;
