#!/bin/bash
set -e
if [ -z "${PYTHON_VERSIONS}" ]; then
   PYTHON_VERSIONS="3.7 3.8 3.9 3.10 3.11 3.12"
fi
if [ -z "${PYENV_ROOT}" ]; then
   export PYENV_ROOT=/usr/local/pyenv
fi
export PATH="${PYENV_ROOT}/bin:$PATH"
if [ -z "${BINJA_DIR}" ]; then
   BINJA_DIR=/opt/rbs
fi
if [ ! -e "${BINJA_DIR}"/binaryninja/scripts/install_api.py ]; then
   echo "Expected ${BINJA_DIR}/binaryninja/scripts/install_api.py to be there, but it's not."
   echo "Is binary ninja installed? Do you have BINJA_DIR defined correctly (defaults to /opt/rbs)?"
   exit 1
fi
if [ ! -e "${PYENV_ROOT}" ]; then
	curl https://pyenv.run | bash
fi
eval "$(pyenv init -)"
for v in ${PYTHON_VERSIONS}; do
   pyenv install -s $v
   pyenv global $v
   python$v -m pip --no-input install --upgrade pip
   python$v -m pip --no-input install requests
   python$v "${BINJA_DIR}"/binaryninja/scripts/install_api.py
   if make OFRAK_INSTALL_PYTHON=python$v install_test_all; then :
   else
      echo "Failed to make and test with Python v $v"
      exit 1
   fi
done
echo "Success!"
