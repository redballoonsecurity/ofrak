PYTHON=python3
PIP=pip3

define COMPILE_FUTHARK
	futhark pyopencl --library ofrak_gpu/entropy.fut -o ofrak_gpu/entropy
endef

.PHONY: install
install:
	$(COMPILE_FUTHARK)
	$(PIP) install .

.PHONY: develop
develop:
	$(COMPILE_FUTHARK)
	$(PIP) install -e .[test]

.PHONY: inspect
inspect:
	mypy

.PHONY: test
test: inspect
	$(PYTHON) -m pytest ofrak_gpu_test --cov=ofrak_gpu --cov-report=term-missing
	fun-coverage --cov-fail-under=100
