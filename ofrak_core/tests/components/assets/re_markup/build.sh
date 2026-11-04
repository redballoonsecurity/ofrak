#!/usr/bin/env bash
# Rebuild the A/B binary pair used by the portable RE markup tests: one program (Lua 5.4.7, MIT
# license) built by two compiler versions, so function addresses differ while most strings are
# shared. The committed binaries were produced on Ubuntu with gcc-11 11.5.0-11ubuntu2 (build A),
# gcc-15 15.2.0-16ubuntu1 (build B) and GNU ld 2.46; other toolchains produce different binaries.
#
# Usage: ./build.sh [OUTPUT_DIR]   (defaults to the directory containing this script)
set -euo pipefail

LUA_VERSION=5.4.7
LUA_SHA256=9fbf5e28ef86c69858f6d3d34eccc32e911c1a28b4120ff3e84aaa70cfbf1e30
OUTPUT_DIR=$(realpath "${1:-$(dirname "$0")}")
WORK_DIR=$(mktemp -d)
trap 'rm -rf "$WORK_DIR"' EXIT

cd "$WORK_DIR"
curl -sSLO "https://www.lua.org/ftp/lua-${LUA_VERSION}.tar.gz"
echo "${LUA_SHA256}  lua-${LUA_VERSION}.tar.gz" | sha256sum --check --quiet
tar -xzf "lua-${LUA_VERSION}.tar.gz"
# Build from inside src/ so the symbol table's STT_FILE entries are bare file names.
cd "lua-${LUA_VERSION}/src"
SOURCES=$(ls ./*.c | grep -v luac.c)

build() {
    local compiler=$1 name=$2
    # The same flags as Lua's own `make linux`, minus `-Wl,-E`: exporting every symbol to the
    # dynamic symbol table would leave all function names in the stripped binary. Non-PIE so that
    # the backend's addresses match the ELF's own section addresses.
    # shellcheck disable=SC2086
    "$compiler" -std=gnu99 -O2 -fno-pie -no-pie -DLUA_COMPAT_5_3 -DLUA_USE_LINUX \
        -o "$OUTPUT_DIR/$name.unstripped" $SOURCES -lm -ldl
    strip --strip-all -o "$OUTPUT_DIR/$name" "$OUTPUT_DIR/$name.unstripped"
}

build gcc-11 lua-gcc11-O2
build gcc-15 lua-gcc15-O2
