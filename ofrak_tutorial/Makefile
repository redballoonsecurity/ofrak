PYTHON=python3
PIP=pip3
BASE_IMAGE_NAME=redballoonsecurity/ofrak/tutorial
commit_short_hash=$(shell git rev-parse --short=8 HEAD)
FULL_IMAGE_NAME=${BASE_IMAGE_NAME}:${commit_short_hash}

.PHONY: run
# Only target in this Makefile to be executed from the host, not a container
run:
	docker run \
		--rm \
		--interactive \
		--tty \
		--publish 8888:8888 \
		--publish 80:80 \
		--name ofrak-tutorial \
		--entrypoint "nginx \
			& python3 -m ofrak_ghidra.server start \
			& python3 /ofrak_server.py 0.0.0.0 8877 \
			& jupyter notebook --no-browser --allow-root --ip 0.0.0.0 --notebook-dir '/ofrak_tutorial/notebooks' \
			& mkdocs serve --dev-addr 0.0.0.0:8000" \
		${FULL_IMAGE_NAME}

.PHONY: develop
develop:
	${PIP} install -e .[test]
	make generate_stripped_notebooks

.PHONY: install
install:
	${PIP} install .
	make generate_stripped_notebooks

.PHONY: inspect
inspect:
	mypy

.PHONY: test
test: inspect
	$(PYTHON) -m pytest ofrak_tutorial_test
	# Note: this requires the Ghidra server to be up and running
	$(PYTHON) -m pytest --nbval --sanitize-with=nbval_sanitizer.cfg --cov=ofrak_tutorial --cov-report=term-missing --cov-fail-under=100 notebooks_with_outputs
	fun-coverage --cov-fail-under=100

.PHONY: generate_stripped_notebooks
generate_stripped_notebooks:
	./generate_stripped_notebooks.sh
