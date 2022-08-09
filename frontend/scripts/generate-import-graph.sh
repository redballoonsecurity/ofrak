#!/bin/bash

GUI_DIR=./src/;

function print-nodes() {
  pushd "${GUI_DIR}" > /dev/null || return;
  REGEX='s'\
'/(^\.\/([^:]+):[[:space:]]*import \{? ?([a-zA-Z0-9, ]*) ?\}? from "\.?\/?(.*)";)'\
'/    "\2" -> "\4";/';
  grep -r -i "import .* from .*" \
    | sed -E "${REGEX}";
  popd > /dev/null || return;
}

function print-component-nodes() {
  print-nodes \
    | grep "\.svelte.*\.svelte";
}

function print-app-imports() {
  print-component-nodes \
    | grep "App.*->" \
    | sed -E 's/^[[:space:]]*"App.svelte" -> (".*");$/\1,/' \
    | grep -v "Loading" \
    | tr '\n' ' ' \
    | sed 's/, $//';
}

function print-loading-rank() {
  print-component-nodes \
    | grep -o '"Loading[^"]*"' \
    | sort \
    | uniq \
    | tr '\n' ',' \
    | sed 's/,/, /g' \
    | sed 's/, $//';
}

echo "digraph G {";
# print-nodes;
print-component-nodes;
echo;
echo -n "    rank=same {";
print-app-imports;
echo "};";
echo -n "    rank=same {";
print-loading-rank;
echo "};";
echo "}";
