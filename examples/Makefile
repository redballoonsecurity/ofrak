PYTHON=python3

.PHONY: install
install:

.PHONY: develop
develop:

.PHONY: test
test:
	$(PYTHON) -m pytest --cov=. --cov-report=term-missing test_examples.py
	fun-coverage --cov-fail-under=100

.PHONY: dependencies
dependencies:
	# Nothing to install
