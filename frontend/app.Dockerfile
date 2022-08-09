FROM node:latest

RUN apt-get update && apt-get install -y sudo

ARG UID
ARG GID

RUN usermod -aG sudo node && \
    (echo node:node | chpasswd) && \
    usermod -u ${UID} node && \
    groupmod -g ${GID} node && \
    usermod -g ${GID} node

WORKDIR /home/node/app
ENTRYPOINT su node -c "npm install && make serve"
