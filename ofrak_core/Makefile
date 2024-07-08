PYTHON=python3
PIP=pip3

.PHONY: install
install: ofrak/gui/public
	$(PIP) install .

.PHONY: develop
develop: ofrak/gui/public
	# Workaround for https://github.com/redballoonsecurity/ofrak/issues/419
	$(PIP) install -e .
	if [ -d ../disassemblers ]; then $(MAKE) -C ../disassemblers/ofrak_angr develop; else $(MAKE) -C ../ofrak_angr develop; fi
	if [ -d ../disassemblers ]; then $(MAKE) -C ../disassemblers/ofrak_capstone develop; else $(MAKE) -C ../ofrak_capstone develop; fi
	$(PIP) install -e .[docs,test]

.PHONY: inspect
inspect:
	mypy

.PHONY: test
test: inspect
	$(PYTHON) -m pytest -n auto test_ofrak --cov=ofrak --cov-report=term-missing
	fun-coverage --cov-fail-under=100

ofrak/gui/public:
	if [ -d /ofrak_gui ] ; then \
		cp -r /ofrak_gui ofrak/gui/public ; \
	elif [ -d ../frontend ]; then \
		cd ../frontend && \
		npm install && \
		npm run build && \
		cd ../ofrak_core && \
		cp -r ../frontend/dist ofrak/gui/public ; \
	fi
