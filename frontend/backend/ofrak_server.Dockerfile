FROM registry.gitlab.com/redballoonsecurity/ofrak/dev:latest

COPY ofrak_server.py /ofrak_server.py
COPY docs /docs
COPY mkdocs.yml /mkdocs.yml

RUN python3 -m pip install aiohttp~=3.8.1

ENTRYPOINT python3 -m ofrak_ghidra.server start \
  & mkdocs serve --dev-addr 0.0.0.0:8000 \
  & python3 /ofrak_server.py 0.0.0.0 8877 ghidra \
  & sleep infinity
