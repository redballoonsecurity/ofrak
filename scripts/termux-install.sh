#!/data/data/com.termux/files/usr/bin/env bash
# ==============================================================
#  OFRAK Termux Installer
#  FAST PATH (default): download & install prebuilt .deb  (~1 min)
#  SLOW PATH (--source / fallback): compile from source   (~40 min)
#
#  Usage:
#    bash termux-install.sh                 # prebuilt .deb (default)
#    bash termux-install.sh --source <dir>  # build from local checkout
#    bash termux-install.sh --build         # force on-device compile from PyPI
# ==============================================================
set -euo pipefail

RED='\033[0;31m'; GREEN='\033[0;32m'; YELLOW='\033[1;33m'; NC='\033[0m'

info()  { echo -e "${GREEN}[+]${NC} $*"; }
warn()  { echo -e "${YELLOW}[!]${NC} $*"; }
die()   { echo -e "${RED}[-] $*${NC}"; exit 1; }

REPO="Opanxxc/ofrak"

if [[ "${PREFIX:-}" != *"com.termux"* ]]; then
  die "This script must be run inside Termux (Android). PREFIX=$PREFIX"
fi

MODE="${1:-}"
SRC_MODE=""
FORCE_BUILD=0
case "$MODE" in
  --source) [[ -n "${2:-}" ]] || die "--source requires a directory argument"
            SRC_MODE="$(realpath "$2")"
            [[ -f "$SRC_MODE/ofrak_core/setup.py" ]] || die "Not an ofrak source tree: $SRC_MODE" ;;
  --build)  FORCE_BUILD=1 ;;
esac

echo "=============================================="
echo "   OFRAK installer for Termux (Android)"
echo "=============================================="

ARCH=$(uname -m)
[[ "$ARCH" == "aarch64" || "$ARCH" == "armv8"* ]] || warn "Unexpected arch: $ARCH (prebuilt deb is aarch64)"

install_source_build() {
  warn "Falling back to on-device compile (this takes ~30-60 min)..."
  pkg update -y
  pkg install -y python python-pip clang make cmake binutils pkg-config \
                 libffi openssl rust git lld ncurses readline zlib
  export CFLAGS="-Wno-deprecated-declarations"
  export CPPFLAGS="-I$PREFIX/include"
  export LDFLAGS="-L$PREFIX/lib"
  # maturin (cryptography rust builds) needs Android API level on Termux
  export ANDROID_API_LEVEL=24
  # CMake >= 4 rejects projects with old cmake_minimum_required (keystone etc.)
  export CMAKE_POLICY_VERSION_MINIMUM=3.5
  # New setuptools (>=81) removed pkg_resources which old sdists import at build time.
  # Pin it via PIP_CONSTRAINT so pip build isolation respects it too.
  printf 'setuptools<81\n' > "$HOME/.ofrak-pip-constraints.txt"
  export PIP_CONSTRAINT="$HOME/.ofrak-pip-constraints.txt"
  pip install --upgrade "pip" "setuptools<81" wheel
  # LIEF: PyPI sdist is a wheel-only stub that refuses 'android - aarch64'.
  # Fetch real source from GitHub (Python bindings live in api/python/).
  echo "[*] Pre-building LIEF from real source..."
  LIEF_URL="https://github.com/lief-project/LIEF/archive/refs/tags/1.0.0.tar.gz"
  curl -sSL "$LIEF_URL" -o "$HOME/lief.tar.gz" 2>/dev/null \
    || curl -sSL "https://github.com/lief-project/LIEF/archive/refs/tags/0.16.1.tar.gz" -o "$HOME/lief.tar.gz"
  rm -rf "$HOME/lief-src" && mkdir -p "$HOME/lief-src"
  tar -xzf "$HOME/lief.tar.gz" -C "$HOME/lief-src" --strip-components=1
  if [ ! -f "$HOME/lief-src/api/python/setup.py" ] && [ ! -f "$HOME/lief-src/api/python/pyproject.toml" ]; then
    die "LIEF python bindings not found in extracted source"
  fi
  # Use Termux's own ninja/cmake (pip ninja wheel doesn't exist for android)
  pkg install -y ninja re2c 2>/dev/null || true
  pip install scikit-build-core tomli pydantic
  pip install -r "$HOME/lief-src/api/python/build-requirements.txt" 2>/dev/null || true
  pip install --no-build-isolation "$HOME/lief-src/api/python"
  # keystone-engine 0.9.2 sets cmake_policy(CMP0051 OLD) which CMake 4 rejects.
  echo "[*] Patching & building keystone-engine (CMake 4 compat)..."
  KSDIR="$HOME/ks-src"
  rm -rf "$KSDIR" && mkdir -p "$KSDIR" && cd "$KSDIR"
  pip download "keystone-engine==0.9.2" --no-deps --no-binary :all: -d "$KSDIR"
  tar xf keystone-engine-*.tar.gz
  KSSRC=$(find "$KSDIR" -maxdepth 1 -type d -name 'keystone-engine-*' | head -1)
  grep -rl 'cmake_policy(SET CMP' "$KSSRC" | while read -r f; do
    sed -i 's/cmake_policy(SET \(CMP[0-9]*\) OLD)/cmake_policy(SET \1 NEW)/g' "$f"
  done
  pip install --no-build-isolation "$KSSRC"
  if [[ -n "$SRC_MODE" ]]; then
    pip install "$SRC_MODE/ofrak_type" "$SRC_MODE/ofrak_io" "$SRC_MODE/ofrak_patch_maker"
    pip install "$SRC_MODE/ofrak_core"
  else
    # Install ofrak CORE from this fork (modern dependency pins, PyPI only has
    # ancient 3.2.0 with aiohttp~=3.8.1 that fails to build on new Python).
    # Helper packages come from PyPI wheels (pure python, safe).
    info "Installing helper packages from PyPI..."
    pip install ofrak-type ofrak-io ofrak-patch-maker
    info "Installing ofrak core from GitHub fork (latest)..."
    pip install --pre "ofrack @ git+https://github.com/$REPO.git#subdirectory=ofrak_core"
  fi
}

install_prebuilt_deb() {
  info "Fetching latest prebuilt Termux .deb..."
  local API="https://api.github.com/repos/$REPO/releases/tags/continuous"
  local URL
  URL=$(curl -sfL "$API" | grep '"browser_download_url"' | cut -d'"' -f4 | grep '_aarch64\.deb$' | head -1) || true
  [[ -n "$URL" ]] || { warn "No aarch64 .deb asset found in continuous release"; return 1; }

  info "Downloading: $URL"
  curl -fL --retry 3 -o /tmp/ofrak-termux.deb "$URL" || return 1

  # Runtime deps for the prebuilt package
  pkg install -y python libffi openssl ncurses readline zlib dpkg || return 1

  info "Installing .deb..."
  apt install -y /tmp/ofrak-termux.deb || dpkg -i /tmp/ofrak-termux.deb || {
    warn ".deb install failed"; rm -f /tmp/ofrak-termux.deb; return 1;
  }
  rm -f /tmp/ofrak-termux.deb
  return 0
}

if [[ -n "$SRC_MODE" ]]; then
  install_source_build
elif [[ $FORCE_BUILD -eq 1 ]]; then
  install_source_build
else
  if ! install_prebuilt_deb; then
    install_source_build
  fi
fi

# --- Also grab the terminal menu if not already installed -----
if ! command -v ofrak-menu >/dev/null 2>&1; then
  curl -sfL "https://raw.githubusercontent.com/$REPO/master/scripts/ofrak-menu.sh" \
    -o "$PREFIX/bin/ofrak-menu" && chmod +x "$PREFIX/bin/ofrak-menu" \
    && info "Installed terminal menu: run 'ofrak-menu'"
fi

# --- Install cryptography (needed by ofrak license module) -----------
info "Installing maturin + cryptography for license verification..."
pip install --no-cache-dir maturin 2>/dev/null || true
pip install --no-cache-dir cffi cryptography 2>/dev/null || warn "cryptography install failed - run: pip install maturin cffi cryptography"

# --- License hint + verify ------------------------------------
command -v ofrak >/dev/null 2>&1 || die "ofrak binary not found in PATH. Check output above."

info "OFRAK installed successfully!"
warn "Accept the community license once:  ofrak license --community --i-agree"
cat <<EOF

==============================================================
 Usage:
   ofrak license --community --i-agree    # first run only
   ofrak-menu                             # TUI - no browser needed!
   ofrak gui                              # web GUI on port 8888
   ofrak list                             # list all components

 Terminal menu: 'ofrak-menu' -> unpack/identify langsung di Termux
 Web GUI: open http://127.0.0.1:8888 in your phone browser
==============================================================
EOF
