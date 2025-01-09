PYTHON=python3
PIP=pip3

.PHONY: install
install:

.PHONY: develop
develop:

.PHONY: test
test:
	$(PYTHON) -m pytest --cov=. --cov-report=term-missing test_examples.py
	fun-coverage --cov-fail-under=100 || ! (shell uname -m | grep x86_64)

.PHONY: dependencies
dependencies:
	# Nothing to install
