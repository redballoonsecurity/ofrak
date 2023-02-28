PYTHON=python3
PIP=pip3

.PHONY: install
install: ofrak/gui/public
	$(PIP) install .

.PHONY: develop
develop: ofrak/gui/public
	$(PIP) install -e .[docs,test]

.PHONY: inspect
inspect:
	mypy
	
.PHONY: serial
serial:
	$(PYTHON) -m pytest -n0 -m "serial" test_ofrak --cov=ofrak --cov-report=term-missing
	fun-coverage 

.PHONY: test
test: inspect serial
	$(PYTHON) -m pytest -n auto -m "not serial" test_ofrak --cov=ofrak --cov-report=term-missing --cov-append
	fun-coverage --cov-fail-under=100

.PHONY: dependencies
dependencies:

ofrak/gui/public:
	if [ -d /ofrak_gui ] ; then \
		cp -r /ofrak_gui ofrak/gui/public ; \
	elif [ -d ../frontend ]; then \
		cd ../frontend && \
		npm run build && \
		cd ../ofrak_core && \
		cp -r ../frontend/public ofrak/gui/public ; \
	fi
