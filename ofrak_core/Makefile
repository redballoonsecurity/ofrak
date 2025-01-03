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
	(sleep 2; echo 1; sleep 2; echo i agree) \
		| python3 -m coverage run --append --source ofrak -m ofrak license --force
	@if [ "$(shell uname -m)" = "x86_64" ]; then \
		fun-coverage --cov-fail-under=100; \
	else \
		fun-coverage; \
	fi

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
