#!/usr/bin/env bash
if [ -f /run/secrets/serial ]; then
    export SERIAL=$(cat /run/secrets/serial)
else
    echo "Error: BinaryNinja license serial number not found." >&2 
    exit 1
fi
INSTALL_DIR=/opt/rbs
mkdir -p $INSTALL_DIR
cd $INSTALL_DIR
curl -O https://raw.githubusercontent.com/Vector35/binaryninja-api/dev/scripts/download_headless.py
python3 -m pip --no-input install requests
python3 download_headless.py --serial $SERIAL
unzip BinaryNinja-headless.zip
rm download_headless.py BinaryNinja-headless.zip
python3 binaryninja/scripts/install_api.py
