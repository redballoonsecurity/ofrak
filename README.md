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

OFRAK can be installed in three ways:

| Method | Best For | Installation Command |
|--------|----------|---------------------|
| **PyPI** | Quick testing, users who prefer managing their own environment | `pip install ofrak` |
| **Docker** | Comprehensive environment with all dependencies, consistent setup | `python3 build_image.py --config ofrak-ghidra.yml --base --finish` |
| **Source** | Contributors, developers, modifying OFRAK code | Clone repo + `make develop` |

See ([Install](docs/install/index.md)) for detailed installation instructions.

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
