#!/bin/bash

# Convert all the notebooks with outputs into notebooks stripped of their outputs.

set -euo pipefail

NOTEBOOKS_WITH_OUTPUTS_DIR=notebooks_with_outputs
NOTEBOOKS_DIR=notebooks

if ! [ -d "${NOTEBOOKS_WITH_OUTPUTS_DIR}" ]; then
  >&2 echo "This should be run from the directory containing ${NOTEBOOKS_WITH_OUTPUTS_DIR}"
  exit 1
fi

mkdir -p "${NOTEBOOKS_DIR}"
cd "${NOTEBOOKS_WITH_OUTPUTS_DIR}"
for notebook in *.ipynb; do
  jupyter nbconvert --clear-output --to=notebook --output="../${NOTEBOOKS_DIR}/${notebook}" "${notebook}"
done
