################################################################################
# Global variables
################################################################################

PORT ?= 8888
OFRAK_SOURCE_DIR ?= $(CURDIR)/..


################################################################################
# Run outside Docker
################################################################################

src/console_art.js: scripts/parse-bbcode.py
	python3 scripts/parse-bbcode.py \
		--export \
		--outfile $@

import-graph.png: scripts/generate-import-graph.sh
	bash "$<" \
		| dot \
			-T png \
			-o "$@"

public/sounds/%.mp3: scripts/download-music.sh
	bash "$<"

.PHONY: lint
lint:
	npm run lint
	python3 -m black scripts/ backend/
	shellcheck scripts/*.sh # https://github.com/koalaman/shellcheck

.PHONY: check
check:
	npm run check
	python3 -m black --check scripts/ backend/
	shellcheck scripts/*.sh # https://github.com/koalaman/shellcheck

.PHONY: app-stack-dev
app-stack-dev: images
	-docker swarm init
	PORT=$(PORT) \
	docker stack deploy --compose-file compose.yml ofrak-stack

.PHONY: stop-app-stack-dev
stop-app-stack-dev:
	docker stack rm ofrak-stack

.PHONY: redeploy-app
redeploy-app: app-stack-dev
	docker service update ofrak-stack_app
	docker service update ofrak-stack_proxy

.PHONY: images
images: app-image ofrak-server-image proxy-image

.PHONY: ofrak-server-image
ofrak-server-image:
	docker build -t rbs/ofrak-server:latest -f backend/ofrak_server.Dockerfile backend

.PHONY: proxy-image
proxy-image:
	DOCKER_BUILDKIT=0 \
	COMPOSE_DOCKER_CLI_BUILD=0 \
	docker build -t rbs/ofrak-gui-proxy:latest -f backend/proxy.Dockerfile backend

.PHONY: app-image
app-image:
	# This build uses the local user and group IDs. This means the rbs/ofrak-gui-app image is not
	# portable to another user or machine.
	DOCKER_BUILDKIT=0 \
	COMPOSE_DOCKER_CLI_BUILD=0 \
	docker build -t rbs/ofrak-gui-app:latest -f app.Dockerfile . --build-arg UID=$(shell id -u) --build-arg GID=$(shell id -g)


################################################################################
# Run inside Node Docker
################################################################################

.PHONY: serve
serve:
	npm run watch


################################################################################
# Run inside OFRAK Docker
################################################################################

.PHONY: install
install:


.PHONY: develop
develop:


.PHONY: test
test:
