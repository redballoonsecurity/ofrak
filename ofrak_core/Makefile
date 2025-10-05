PYTHON=python3
PIP=pip3

.PHONY: install
install: src/ofrak/gui/public
	$(PIP) install .

.PHONY: develop
develop: src/ofrak/gui/public
	$(PIP) install -r requirements.txt -r requirements-docs.txt -r requirements-non-pypi.txt -r requirements-test.txt
	$(PIP) install -e . --config-settings editable_mode=compat

.PHONY: inspect
inspect:
	mypy

.PHONY: test
test: inspect
	$(PYTHON) -m pytest -n auto tests --cov=ofrak --cov-report=term-missing
	(sleep 2; echo 1; sleep 2; echo i agree) \
		| python3 -m coverage run --append --source ofrak -m ofrak license --force
	fun-coverage --cov-fail-under=100

.PHONY: test-wheel  
test-wheel: inspect  
	$(PYTHON) -m pytest --skip-tests-missing-deps tests/service

src/ofrak/gui/public:
	if [ -d /ofrak_gui ] ; then \
		cp -r /ofrak_gui src/ofrak/gui/public ; \
	elif [ -d ../frontend ]; then \
		cd ../frontend && \
		npm install && \
		VITE_OFRAK_VERSION="$(shell python3 -c "from src.ofrak.version import VERSION; print(VERSION)")" \
		npm run build && \
		cd ../ofrak_core && \
		cp -r ../frontend/dist src/ofrak/gui/public ; \
	fi
