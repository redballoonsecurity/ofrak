FROM redballoonsecurity/ofrak/dev:latest

ARG BACKEND_DIR=.

RUN python3 -m pip install aiohttp~=3.9.3

ENTRYPOINT python3 -m ofrak_ghidra.server start \
  & python3 -m ofrak gui -H 0.0.0.0 -p 8877 \
  & sleep infinity
