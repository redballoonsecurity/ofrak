PYTHON=python3

.PHONY: install
install:

.PHONY: develop
develop:

.PHONY: test
test:
	$(PYTHON) -m pytest --asyncio-mode=auto --cov=. --cov-report=term-missing test_examples.py test_fs_convert.py
	fun-coverage --cov-fail-under=100

.PHONY: dependencies
dependencies:
	# Nothing to install
