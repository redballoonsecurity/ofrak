# OFRAK

OFRAK (Open Firmware Reverse Analysis Konsole) is a binary analysis and modification platform. OFRAK combines the ability to:

- **Identify** and **Unpack** many binary formats
- **Analyze** unpacked binaries with field-tested reverse engineering tools
- **Modify** and **Repack** binaries with powerful patching strategies

OFRAK supports a range of embedded firmware file formats beyond userspace executables, including:

- Compressed filesystems
- Compressed & checksummed firmware
- Bootloaders
- RTOS/OS kernels

OFRAK equips users with:

- A **Graphical User Interface (GUI)** for interactive exploration and visualization of binaries
- A **Python API** for readable and reproducible scripts that can be applied to entire classes of binaries, rather than just one specific binary
- Recursive **identification, unpacking, and repacking** of many file formats, from ELF executables, to filesystem archives, to compressed and checksummed firmware formats
- Built-in, extensible **integration with powerful analysis backends** (angr, Binary Ninja, Ghidra, IDA Pro)
- **Extensibility by design** via a common interface to easily write additional OFRAK components and add support for a new file format or binary patching operation

See [ofrak.com](https://ofrak.com) for more details.

## GUI Frontend

The web-based GUI view provides a navigable resource tree. For the selected resource, it also provides: metadata, hex or text navigation, and a mini map sidebar for quickly navigating by entropy, byteclass, or magnitude. The GUI also allows for actions normally available through the Python API like commenting, unpacking, analyzing, modifying and packing resources.

<div align="center">
<img src="docs/assets/ofrak_gui_1.png">
</div>

## Getting Started

### Installation Methods

OFRAK can be installed in four ways:

| Method | Best For | Installation Command |
|--------|----------|---------------------|
| **.deb / .AppImage** (this fork) | Ready-to-use desktop install with bundled Python 3.13 + GUI | Download from [Releases](https://github.com/Opanxxc/ofrak/releases) |
| **PyPI** | Quick testing, users who prefer managing their own environment | `pip install ofrak` |
| **Docker** | Comprehensive environment with all dependencies, consistent setup | `python3 build_image.py --config ofrak-ghidra.yml --base --finish` |
| **Source** | Contributors, developers, modifying OFRAK code | Clone repo + `make develop` |

**Install via .deb (Debian/Ubuntu):**

```bash
sudo apt install ./ofrak_*_amd64.deb
ofrak license --community --i-agree   # first run only
ofrak gui                             # opens web GUI at http://localhost:8888
```

**Run via .AppImage (any distro):**

```bash
chmod +x OFRAK-*-x86_64.AppImage
./OFRAK-*-x86_64.AppImage license --community --i-agree
./OFRAK-*-x86_64.AppImage gui
```

Both packages bundle a standalone Python 3.13 interpreter and the pre-built GUI frontend — no system Python or Node.js required.

**Install on Android via Termux (recommended):**

Option A — One-liner (auto-downloads prebuilt .deb, ~1 min):
```bash
curl -sL https://raw.githubusercontent.com/Opanxxc/ofrak/master/scripts/termux-install.sh | bash
```

Option B — Manual install with wget:
```bash
# 1. Install Termux from F-Droid (not Play Store)
# 2. Open Termux and run:
pkg update && pkg install git

# 3. Download the latest prebuilt .deb
cd $HOME
wget -q https://github.com/Opanxxc/ofrak/releases/download/continuous/ofrak_3.4.0_aarch64.deb

# 4. Install it
apt install -y ./ofrak_3.4.0_aarch64.deb

# 5. Accept the community license (first run only)
ofrak license --community --i-agree

# 6. Launch the GUI
ofrak gui
# Open http://127.0.0.1:8888 in your phone browser

# Or use the terminal menu (no browser needed):
ofrak-menu
```

The Termux .deb includes:
- **ofrak core** — unpack, identify, modify, repack
- **ofrak_angr** — angr-based symbolic analysis backend
- **ofrak_capstone** — capstone disassembly engine
- **GUI frontend** — web-based resource explorer
- **TUI menu** — `ofrak-menu` for terminal-only usage

If you need Ghidra integration, install it manually:
```bash
pip install ofrak_ghidra
```

**Build from source (20-40 min on device):**
```bash
curl -sL https://raw.githubusercontent.com/Opanxxc/ofrak/master/scripts/termux-install.sh | bash -s -- --build
```

See ([Install](docs/install/index.md)) for detailed installation instructions.

Note that OFRAK uses Git LFS -- see [Installing from Source](docs/install/source.md) for more details.

## Documentation

OFRAK has general documentation and API documentation. Both can be viewed at [ofrak.com/docs](https://ofrak.com/docs).

If you wish to make changes to the documentation or serve it yourself, follow the directions in [`docs/README.md`](docs/README.md).

## License

The code in this repository comes with an [OFRAK Community License](LICENSE), which is intended for educational uses, personal development, or just having fun.
If the community license is right for you, run `ofrak license --community --i-agree` to accept it!

Users interested in OFRAK for commercial purposes can request the Pro or Enterprise License. See [OFRAK Licensing](https://ofrak.com/license/) for more information.

## Contributing

Red Balloon Security is excited for security researchers and developers to contribute to this repository.

For details, please see our [contributor guide](CONTRIBUTING.md) and the [Python development guide](docs/contributor-guide/getting-started.md).

## Support

Please contact [ofrak@redballoonsecurity.com](mailto:ofrak@redballoonsecurity.com), or write to us on [the OFRAK Slack](https://join.slack.com/t/ofrak/shared_invite/zt-1jku9h6r5-mY7CeeZ4AT8JVmu5YWw2Qg) with any questions or issues regarding OFRAK. We look forward to getting your feedback! Sign up for the [OFRAK Mailing List](https://ofrak.com/sign-up) to receive monthly updates about OFRAK code improvements and new features.

---

*This material is based in part upon work supported by the DARPA under Contract No. N66001-20-C-4032. Any opinions, findings and conclusions or recommendations expressed in this material are those of the author(s) and do not necessarily reflect the views of the DARPA. Distribution Statement “A” (Approved for Public Release, Distribution Unlimited).*
