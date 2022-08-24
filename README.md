# OFRAK
OFRAK (Open Firmware Reverse Analysis Konsole) is a binary analysis and modification platform that combines the ability unpack, analyze, modify, and repack binaries.

OFRAK combines the ability to:

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

### GUI Frontend
The GUI view provides a navigable resource tree, and for the selected resource: metadata, hex navigation, and an
entropy / byteclass / magnitude map sidebar. The GUI also allows for actions normally available through the python API
like commenting, unpacking, analysis, modification and packing of resources.

<div align="center">
<img id="ofrak-animation" src="docs/assets/ofrak_gui_1.png" style="max-width:1000px;width:100%">
</div>


## Getting Started
See [INSTALL.md](https://github.com/redballoonsecurity/ofrak/blob/master/INSTALL.md) for instructions on how to install OFRAK.

**OFRAK uses Git LFS. This means that you must have Git LFS installed before you clone the repository!** Install Git LFS by following [the instructions here](https://git-lfs.github.com/). If you accidentally cloned the repository before installing Git LFS, `cd` into the repository and run `git lfs pull`.

## License
The code in this repository comes with an [OFRAK Community License](https://github.com/redballoonsecurity/ofrak/blob/master/LICENSE), which is intended for educational uses, personal development, or just having fun.

Users interested in using OFRAK for commercial purposes can request the Pro License, which for a limited period is available for a free 6-month trial. See [OFRAK Licensing](https://ofrak.com/license/) for more information.

## Documentation
OFRAK has general documentation and API documentation. They can be viewed at <https://ofrak.com/docs>.

If you wish to make changes to the documentation or serve it yourself, once OFRAK has been installed, run `make develop` in each of `ofrak_type`, `ofrak_io`, `ofrak_core`, and `ofrak_patch_maker` to install the dependencies needed to work with this documentation source.

The source for OFRAK's documentation resides in `./docs` and is built using [MkDocs](https://www.mkdocs.org/).

`mkdocs.yml` contains the configuration information for that source.

To host and view documents locally, run the following command from the root directory of this repository:
```
% mkdocs serve
INFO     -  Building documentation...
INFO     -  Cleaning site directory
INFO     -  Documentation built in 0.14 seconds
INFO     -  [23:59:36] Serving on http://127.0.0.1:8000/```
```

Note that the docs must be built (or served using `mkdocs serve`) in an environment with all Python dependencies installed.

## Contributing

Red Balloon Security is excited for security researchers and developers to contribute to this repository.

As provided by Clause #3 in [our license](./LICENSE), by submitting a Pull Request you are providing
Red Balloon Security, Inc with certain rights to your contribution, and you attest that you are
authorized to do so by anyone who has claims to the content.

Red Balloon Security will not accept Pull Requests nor add software to this repository that reveals information about a
third party's intellectual property, proprietary formats, or protocols, _unless_ they are approved by the (verified)
owner before being created.

Such ownership verification, non-technical questions, concerns, or comments about anything other than
the committed source code should be directed to [ofrak@redballoonsecurity.com](mailto:ofrak@redballoonsecurity.com).

For more details, please see our [contributor guide](https://github.com/redballoonsecurity/ofrak/blob/master/docs/contributing.md).

## Support
Please contact [ofrak@redballoonsecurity.com](mailto:ofrak@redballoonsecurity.com), or write to us on [the OFRAK Slack](https://join.slack.com/t/ofrak/shared_invite/zt-1dywj33gw-DcicqLmzgbdeRTCSF0A_Jg) with any questions or issues regarding OFRAK. We look forward to getting your feedback! Sign up for the [OFRAK Mailing List](https://ofrak.com/sign-up) to receive monthly updates about OFRAK code improvements and new features.

---

*This material is based in part upon work supported by the DARPA under Contract No. N66001-20-C-4032. Any opinions, findings and conclusions or recommendations expressed in this material are those of the author(s) and do not necessarily reflect the views of the DARPA. Distribution Statement “A” (Approved for Public Release, Distribution Unlimited).*
