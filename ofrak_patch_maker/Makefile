PYTHON=python3
PIP=pip3
ETC=/etc


# toolchain.conf is a file mapping ID to the various binaries responsible for preprocessing,
#  assembling, compiling, linking, analyzing binaries for each currently supported toolchain.
$(ETC)/toolchain.conf: ofrak_patch_maker/toolchain.conf
	mkdir -p $(ETC)
	cp -a $< $@

.PHONY: install
install: $(ETC)/toolchain.conf
	$(PIP) install .

.PHONY: develop
develop: $(ETC)/toolchain.conf
	$(PIP) install -e .[test]

.PHONY: inspect
inspect:
	mypy

.PHONY: test
test: inspect
	$(PYTHON) -m pytest -n auto --cov=ofrak_patch_maker --cov-report=term-missing ofrak_patch_maker_test
	fun-coverage --cov-fail-under=100
