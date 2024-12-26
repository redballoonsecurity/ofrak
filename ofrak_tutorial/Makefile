PYTHON=python3
PIP=pip3
BASE_IMAGE_NAME=redballoonsecurity/ofrak/tutorial
commit_short_hash=$(shell git rev-parse --short=8 HEAD)
FULL_IMAGE_NAME=${BASE_IMAGE_NAME}:${commit_short_hash}

# Only target in this Makefile to be executed from the host, not a container.
# 
# Note that the arguments at the end are passed to the bash entrypoint, but that
# the --entrypoint argument must come before the image name.
.PHONY: run
run:
	docker run \
		--rm \
		--detach \
		--interactive \
		--tty \
		--publish 8888:8888 \
		--publish 80:80 \
		--name ofrak-tutorial \
		--entrypoint bash \
		${FULL_IMAGE_NAME} \
		-c 'nginx \
			& python3 -m ofrak gui -H 0.0.0.0 -p 8877 \
			& jupyter notebook --no-browser --allow-root --ip 0.0.0.0 --notebook-dir "/ofrak_tutorial/notebooks" --NotebookApp.port 8888 --NotebookApp.token "" --NotebookApp.password "" \
			& mkdocs serve --dev-addr 0.0.0.0:8000 \
			& python3 -m ofrak_ghidra.server start \
			& sleep infinity'

.PHONY: develop
develop:
	${PIP} install -e .[test] --config-settings editable_mode=strict
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
	$(PYTHON) -m pytest -n auto ofrak_tutorial_test
	# Note: this requires the Ghidra server to be up and running
	$(PYTHON) -m pytest --nbval --sanitize-with=nbval_sanitizer.cfg --cov=ofrak_tutorial --cov-report=term-missing --cov-fail-under=100 notebooks_with_outputs
	fun-coverage --cov-fail-under=100

.PHONY: generate_stripped_notebooks
generate_stripped_notebooks:
	./generate_stripped_notebooks.sh
