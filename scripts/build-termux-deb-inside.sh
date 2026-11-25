#!/data/data/com.termux/files/usr/bin/env bash
# ==============================================================
#  Runs INSIDE termux/termux-docker:aarch64 container.
#  Compiles OFRAK + deps natively against Bionic/Termux, then
#  packages everything into a Termux-format .deb (aarch64).
#
#  Host mounts repo at /work; output deb copied back to /work/
# ==============================================================
set -euo pipefail

PREFIX=/data/data/com.termux/files/usr
export PATH="$PREFIX/bin:$PATH"
export HOME="${HOME:-/root}"
export DEBIAN_FRONTEND=noninteractive
: "${OFRAK_DEB_VERSION:=3.4.0}"

echo "[*] Updating Termux packages..."
# Force official repo to avoid out-of-sync mirrors
cat > "$PREFIX/etc/apt/sources.list" << 'REPO'
deb https://packages.termux.org/apt/termux-main stable main
REPO
pkg update -y || { echo "[!] Retrying pkg update..."; pkg update -y; }
pkg upgrade -y || true

echo "[*] Installing build dependencies..."
pkg install -y \
  python python-pip \
  clang make cmake binutils pkg-config \
  libffi openssl rust git lld \
  ncurses readline zlib dpkg \
  ninja re2c

export CFLAGS="-Wno-deprecated-declarations"
export CPPFLAGS="-I$PREFIX/include"
export LDFLAGS="-L$PREFIX/lib -Wl,-rpath=$PREFIX/lib"
# maturin (cryptography rust builds) needs the Android API level on Termux
export ANDROID_API_LEVEL=24
export CARGO_BUILD_TARGET="aarch64-linux-android"
# CMake >= 4 rejects projects with old cmake_minimum_required (keystone etc.)
export CMAKE_POLICY_VERSION_MINIMUM=3.5
# New setuptools removed pkg_resources which some sdists import at build time
# NOTE: Termux has no writable /tmp - use $HOME instead
printf 'setuptools<81\n' > "$HOME/.pip-constraints.txt"
export PIP_CONSTRAINT="$HOME/.pip-constraints.txt"

echo "[*] Upgrading pip/setuptools/wheel..."
python3 -m pip install --upgrade pip setuptools wheel

echo "[*] Copying sources to writable dir (/work may be read-only)..."
BUILDDIR="$HOME/build"
rm -rf "$BUILDDIR" && mkdir -p "$BUILDDIR"
cp -r /work/ofrak_type /work/ofrak_io /work/ofrak_patch_maker /work/ofrak_core "$BUILDDIR/"
mkdir -p "$HOME/scripts"
cp /work/scripts/ofrak-menu.sh "$HOME/scripts/" 2>/dev/null || true

echo "[*] Compiling & installing OFRAK packages (this takes a while)..."
# LIEF: PyPI sdist is a wheel-only stub that refuses 'android - aarch64'.
# Install the REAL source from GitHub (Python bindings live in api/python/).
echo "[*] Pre-building LIEF from real source (bypasses PyPI stub)..."
LIEF_URL="https://github.com/lief-project/LIEF/archive/refs/tags/1.0.0.tar.gz"
curl -sSL "$LIEF_URL" -o "$HOME/lief.tar.gz" 2>/dev/null \
  || curl -sSL "https://github.com/lief-project/LIEF/archive/refs/tags/0.16.1.tar.gz" -o "$HOME/lief.tar.gz" \
  || python3 -c "import urllib.request as u; u.urlretrieve('$LIEF_URL','$HOME/lief.tar.gz')"
rm -rf "$HOME/lief-src" && mkdir -p "$HOME/lief-src"
tar -xzf "$HOME/lief.tar.gz" -C "$HOME/lief-src" --strip-components=1
if [ ! -f "$HOME/lief-src/api/python/setup.py" ] && [ ! -f "$HOME/lief-src/api/python/pyproject.toml" ]; then
  echo "[-] LIEF python bindings not found"; ls "$HOME/lief-src/api/" || true; exit 1
fi
# Use Termux's own ninja/cmake (pip ninja wheel doesn't exist for android)
python3 -m pip install scikit-build-core tomli pydantic
python3 -m pip install -r "$HOME/lief-src/api/python/build-requirements.txt" 2>/dev/null || true
python3 -m pip install --no-build-isolation "$HOME/lief-src/api/python"
# keystone-engine 0.9.2 sets cmake_policy(CMP0051 OLD) which CMake 4 rejects.
# Download sdist, patch OLD -> NEW, build locally.
echo "[*] Patching & building keystone-engine (CMake 4 compat)..."
KSDIR="$HOME/ks-src"
rm -rf "$KSDIR" && mkdir -p "$KSDIR" && cd "$KSDIR"
python3 -m pip download "keystone-engine==0.9.2" --no-deps --no-binary :all: -d "$KSDIR"
tar xf keystone-engine-*.tar.gz
KSSRC=$(find "$KSDIR" -maxdepth 1 -type d -name 'keystone-engine-*' | head -1)
grep -rl 'cmake_policy(SET CMP' "$KSSRC" | while read -r f; do
  sed -i 's/cmake_policy(SET \(CMP[0-9]*\) OLD)/cmake_policy(SET \1 NEW)/g' "$f"
done
python3 -m pip install --no-build-isolation "$KSSRC"
python3 -m pip install \
  "$BUILDDIR/ofrak_type" \
  "$BUILDDIR/ofrak_io" \
  "$BUILDDIR/ofrak_patch_maker"
python3 -m pip install "$BUILDDIR/ofrak_core"

echo "[*] Installing optional plugins (angr, capstone)..."
# ofrak_angr: angr-based disassembly backend (open source, very useful)
# ofrak_capstone: capstone-based disassembly (lightweight, no LLVM needed)
python3 -m pip install ofrak_angr ofrak_capstone 2>&1 | tail -5 || \
  echo "[!] Plugin install failed (core still works)"

echo "[*] Verifying install..."
command -v ofrak >/dev/null || { echo "[-] ofrak binary missing"; ls "$PREFIX/bin" | grep -i ofr || true; exit 1; }
ofrak list 2>/dev/null | head -5 || echo "[!] ofrak list failed (may be py3.14 compat, deb still valid)"

# --- Stage into Termux filesystem layout ----------------------
PYVER=$(python3 -c 'import sys; print(f"{sys.version_info.major}.{sys.version_info.minor}")')
SP="$PREFIX/lib/python$PYVER/site-packages"
STAGE="$HOME/debstage"
rm -rf "$STAGE"
mkdir -p "$STAGE/data/data/com.termux/files/usr/lib/python$PYVER" \
         "$STAGE/data/data/com.termux/files/usr/bin" \
         "$STAGE/DEBIAN"

echo "[*] Staging site-packages (ofrak only)..."
SP_DIR="$STAGE/data/data/com.termux/files/usr/lib/python$PYVER/site-packages"
mkdir -p "$SP_DIR"
cp -r "$SP/"* "$SP_DIR/" 2>/dev/null || true

# ── Aggressive blacklist: remove EVERYTHING that ships with Termux packages ──
# These conflict with system packages and cause dpkg errors.
BLACKLIST_PKGS=(
  pip setuptools wheel ensurepip
  _distutils_hack distutils pkg_resources
  tkinter turtledemo idlelib lib2to3
  email test test_ pydoc
  _colorsys _compat_pickle _compression _markupbase
  _pylong _scproxy dbm idle_test imaplib imghdr mailcap
  mhlib nntplib pipes sndhdr sunau telnetlib uu whatchangediff
  __phello__ http server _osx_support
  cryptography cffi _cffi_backend maturin
)
for name in "${BLACKLIST_PKGS[@]}"; do
  # Remove directory if it exists
  rm -rf "$SP_DIR/$name" 2>/dev/null || true
  # Also remove any files matching name* (e.g. _cffi_backend.cpython-314-*.so)
  find "$SP_DIR" -maxdepth 1 \( -name "$name" -o -name "${name}.*" \) -exec rm -rf {} + 2>/dev/null || true
  # Remove dist-info for the package
  find "$SP_DIR" -maxdepth 1 -name "${name}*.dist-info" -type d -exec rm -rf {} + 2>/dev/null || true
done

# Remove ALL .so files for abi3-incompatible packages (catch python-tagged ones)
find "$SP_DIR" -maxdepth 1 -name '_cffi_backend*.so' -delete 2>/dev/null || true
find "$SP_DIR" -maxdepth 1 -name '_cffi_backend*.cpython-*' -delete 2>/dev/null || true

# Remove .pyc, __pycache__, README files
find "$SP_DIR" -name '*.pyc' -delete 2>/dev/null || true
find "$SP_DIR" -name '__pycache__' -type d -exec rm -rf {} + 2>/dev/null || true
find "$SP_DIR" -maxdepth 1 -name 'README*' -type f -delete 2>/dev/null || true
rm -f "$SP_DIR/README.txt" "$SP_DIR/README" "$SP_DIR/README.md"

# Remove .pth files that reference deleted modules (distutils-precedence.pth etc.)
find "$SP_DIR" -maxdepth 1 -name '*.pth' -delete 2>/dev/null || true

# Remove any remaining dist-info for blacklisted packages
for name in "${BLACKLIST_PKGS[@]}"; do
  find "$SP_DIR" -maxdepth 1 -name "${name}*.dist-info" -type d -exec rm -rf {} + 2>/dev/null || true
done

echo "[*] After cleanup: $(ls "$SP_DIR" | wc -l) packages in deb"

# Ship the CLI wrapper + terminal UI menu
cp "$PREFIX/bin/ofrak" "$STAGE/data/data/com.termux/files/usr/bin/ofrak"
ln -sf ofrak "$STAGE/data/data/com.termux/files/usr/bin/ofrack"
cp "$HOME/scripts/ofrak-menu.sh" "$STAGE/data/data/com.termux/files/usr/bin/ofrak-menu"
chmod +x "$STAGE/data/data/com.termux/files/usr/bin/ofrak-menu"

cat > "$STAGE/DEBIAN/control" << EOF
Package: ofrak
Version: ${OFRAK_DEB_VERSION}
Section: devel
Priority: optional
Architecture: aarch64
Installed-Size: $(du -sk "$STAGE/data" | cut -f1)
Maintainer: Opanxxc <opanxxc@users.noreply.github.com>
Depends: python (>= ${PYVER}), python-pip, libffi, openssl, ncurses, readline, zlib, rust, binutils
Description: OFRAK - unpack, modify, and repack binaries (Termux build)
 Open Firmware Reverse Analysis Konsole. Binary analysis and
 modification platform with web GUI and Python API.
 Precompiled for Termux aarch64 - no compilation needed.
 Run 'ofrak license --community --i-agree' on first use,
 then 'ofrak gui' and open http://127.0.0.1:8888
Homepage: https://github.com/Opanxxc/ofrak
EOF

# Create postinst - try to install cryptography for full license verification.
# ofrak works without it (lazy import), but license verification needs it.
mkdir -p "$STAGE/DEBIAN"
cat > "$STAGE/DEBIAN/postinst" << 'POSTINST'
#!/data/data/com.termux/files/usr/bin/env bash
# Non-fatal: ofrak works without cryptography (lazy import)
PREFIX=/data/data/com.termux/files/usr
export PATH="$PREFIX/bin:$PATH"
echo "[*] Installing maturin (Rust build backend)..."
"$PREFIX/bin/python3" -m pip install --no-cache-dir maturin 2>/dev/null || true
echo "[*] Installing cryptography (optional, for license verification)..."
"$PREFIX/bin/python3" -m pip install --no-cache-dir cffi cryptography 2>&1 | tail -3 || \
  echo "[i] cryptography skipped - ofrak works without it"
echo "[+] postinst done"
POSTINST
chmod 755 "$STAGE/DEBIAN/postinst"

echo "[*] Building .deb..."
# Build in HOME (guaranteed writable), workflow will docker-cp it out.
DEB_OUT="$HOME/ofrak_${OFRAK_DEB_VERSION}_aarch64.deb"
if dpkg-deb --root-owner-group --build "$STAGE" "$DEB_OUT" 2>/dev/null; then :;
else dpkg-deb --build "$STAGE" "$DEB_OUT"; fi
ls -la "$DEB_OUT"
echo "[+] DONE: $DEB_OUT"
