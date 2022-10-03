PYTHON=python3
PIP=pip3


# toolchain.conf is a file mapping ID to the various binaries responsible for preprocessing,
#  assembling, compiling, linking, analyzing binaries for each currently supported toolchain.
.PHONY: toolchain_conf
toolchain_conf:
	cp toolchain.conf /etc/toolchain.conf
	mv toolchain.conf toolchain.conf.bak

.PHONY: install
install: toolchain_conf
	$(PIP) install .

.PHONY: develop
develop: toolchain_conf
	$(PIP) install -e .[test]

.PHONY: inspect
inspect:
	mypy

.PHONY: test
test: inspect
	$(PYTHON) -m pytest --cov=ofrak_patch_maker --cov-report=term-missing ofrak_patch_maker_test
	fun-coverage --cov-fail-under=79

.PHONY: dependencies
dependencies:

clean:
	-rm -rf lib
