#!/bin/bash

pushd public/sounds || exit;

curl \
    --silent \
    --location "http://www.nihilore.com/synthwave" \
  | grep \
    --only-matching \
    "http.*mp3" \
  | head -n 5 \
  | xargs \
    -L 1 \
    -P 0 \
    wget \
      --no-verbose \
      --no-clobber;

popd || exit;

TEMP_FILE="$(mktemp)";

tr '\n' '\r' \
  < src/AudioPlayer.svelte \
  | sed "s:const sources = \[[^]]*\]:const sources = [$( \
    find public/sounds/ -type f -print0 \
      | xargs -0 -L 1 basename \
      | sed -E -e 's:^(.*)$:"/sounds/\1", :g'  \
      | tr '\n' ' ' \
    )]:g" \
  | tr '\r' '\n' \
  > "${TEMP_FILE}";
mv "${TEMP_FILE}" src/AudioPlayer.svelte;

make lint;
