PYTHON=python3
PIP=pip3

.PHONY: install
install:
	$(PIP) install .

.PHONY: develop
develop:
	$(PIP) install -e .[test]

.PHONY: futhark
futhark:
	futhark pyopencl --library ofrak_gpu/entropy.fut -o ofrak_gpu/entropy

.PHONY: inspect
inspect:
	mypy

.PHONY: test
test: inspect
	$(PYTHON) -m pytest ofrak_gpu_test --cov=ofrak_gpu --cov-report=term-missing
	fun-coverage --cov-fail-under=100
