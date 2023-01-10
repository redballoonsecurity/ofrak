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

.PHONY: test
test: inspect
	$(PYTHON) -m pytest -n auto test_ofrak --cov=ofrak --cov-report=term-missing
	fun-coverage --cov-fail-under=100

.PHONY: dependencies
dependencies:

ofrak/gui/public:
	if [ -d /ofrak_gui ] ; then \
		cp -r /ofrak_gui ofrak/gui/public ; \
	else \
		pushd ../frontend ; \
		npm run build ; \
		popd ; \
		cp -r ../frontend/public ofrak/gui/public ; \
	fi
