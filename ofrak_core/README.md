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

# Package: ofrak

```
OFRAK
└───ofrak  <-- //YOU ARE HERE//
│   └───component   // Definitions for abstract Component classes (e.g. Analyzer)
│   └───core        // Definitions for common software and reverse engineering abstractions
│   └───model       // Definitions for core OFRAK data structures
│   └───service     // Definitions for core OFRAK services
│   
└───ofrak_components
└───ofrak_type
└───ofrak_io
└───ofrak_patch_maker
└───ofrak_tutorial
```

This is the package containing the core of the OFRAK framework. Install this first to get started with OFRAK!

What is included:

- Definitions for core OFRAK data structures and services, such as `Resource`, `OFRAKContext`, and `DataService`.
- Components to handle unpacking, modifying, and repacking common executable file formats:
  - ELF
  - PE Files
- Definitions for common software and reverse engineering abstractions like `Instruction`, `File`, and `BasicBlock`
- Miscellaneous helpful components:
  - `MagicAnalyzer` and two Identifier components which uses `python-libmagic` to automatically tag OFRAK `Resource`s
  - Basic modifiers like `StringFindReplaceModifier` and `BinaryInjectorModifier`
  - Basic useful analyzers like `Sha256Analyzer` and `MD5Analyzer` which calculate the respective checksums of OFRAK `Resource`s

This is only a representative sampling of the features in the core OFRAK. Consult the code reference [docs](https://ofrak.com/docs) for a complete manifest.

What is *not* included:
- The OFRAK PatchMaker
- Components (e.g. unpackers) for other filesystems and file formats like tar, ZIP, SquashFS, RAR, UImage, and more. These are in the `ofrak_components` package and have heavier dependencies
- Components which integrate the disassembler backends (Ghidra, BinaryNinja, Angr, Capstone)

## License
The code in this repository comes with an [OFRAK Community License](https://github.com/redballoonsecurity/ofrak/blob/master/LICENSE), which is intended for educational uses, personal development, or just having fun.

Users interested in using OFRAK for commercial purposes can request the Pro License, which for a limited period is available for a free 6-month trial. See [OFRAK Licensing](https://ofrak.com/license/) for more information.

## Documentation
OFRAK has general documentation and API documentation, which can be viewed at <https://ofrak.com/docs>.
