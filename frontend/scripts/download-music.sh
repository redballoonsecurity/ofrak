#!/bin/bash

TEMP_FILE="$(mktemp)";

tr '\n' '\r' \
  < src/AudioPlayer.svelte \
  | sed "s:const sources = \[[^]]*\]:const sources = [$( \
    curl \
        --silent \
        --location "http://www.nihilore.com/synthwave" \
      | grep \
        --only-matching \
        "http.*mp3" \
      | head -n 5 \
      | sed -E -e 's:^(.*)$:"\1", :g' \
      | sed 's/:/\\:/g' \
      | tr '\n' ' ' \
    )]:g" \
  | tr '\r' '\n' \
  > "${TEMP_FILE}";
mv "${TEMP_FILE}" src/AudioPlayer.svelte;

make lint;
