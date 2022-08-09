#!/bin/bash
set -e

GHIDRA_PATH=$1
OFRAK_GHIDRA_SCRIPTS_PATH=$2

# cd /opt/rbs/ghidra_10.1.2_PUBLIC
cd ${GHIDRA_PATH}
./server/svrInstall

# The following command sometimes fails for unclear reasons, so we give it a few tries.
max_retries=5
retry_counter=0
while ! ./server/svrAdmin -add root; do
  if [ $retry_counter -ge $max_retries ]; then
    echo "Failure running './server/svrAdmin -add root'. Retried $retry_counter times." >&2
    exit 1
  fi
  # Use ++v instead of v++ since bash returns 1 when an arithmetic operation returns 0,
  # and we exit on failures with `set -e`.
  ((++retry_counter))
  sleep 0.5
  echo "Retrying running './server/svrAdmin -add root' ($retry_counter/$max_retries)..."
done

./server/ghidraSvr restart
./support/analyzeHeadless . dummy -postScript CreateRepository.java -scriptPath ${OFRAK_GHIDRA_SCRIPTS_PATH} -deleteProject -noanalysis
