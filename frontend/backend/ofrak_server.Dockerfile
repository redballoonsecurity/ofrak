FROM redballoonsecurity/ofrak/dev:latest

ARG BACKEND_DIR=.
COPY $BACKEND_DIR/ofrak_server.py /ofrak_server.py

RUN python3 -m pip install aiohttp~=3.8.1

ENTRYPOINT python3 -m ofrak_ghidra.server start \
  & python3 /ofrak_server.py 0.0.0.0 8877 \
  & sleep infinity
