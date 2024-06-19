PYTHON=python3
PIP=pip3
STAGE=2

.PHONY: install
install: ofrak/gui/public
	$(PIP) install .


# Workaround for cyclic test dependencies
# https://github.com/redballoonsecurity/ofrak/issues/419
ifeq ($(STAGE), 1)
DEVELOP_TARGET=.
else
DEVELOP_TARGET=.[docs,test]
endif

.PHONY: develop
develop: ofrak/gui/public
	$(PIP) install -e $(DEVELOP_TARGET)

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
		npm run build && \
		cd ../ofrak_core && \
		cp -r ../frontend/dist ofrak/gui/public ; \
	fi
