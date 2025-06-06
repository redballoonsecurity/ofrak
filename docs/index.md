<div align="center">
<img id="ofrak-animation" src="assets/animation.png">
</div>

<!-- Empty title tag is required so mkdocs doesn't automatically add one -->
<h1></h1>

> *To the past, or to the future. To an age when firmware is transparent. From
> the age of the DMCA, from the age of the tyrannous embedded device vendor,
> from a de-obfuscator of the secret sauce... greetings!*
>
> *-0xAC*

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

#### Layout:
```
  ,_________.___________._____________________.___________.
  | Actions | Resource  |       HEX view      | Visualizer |
  |         | tree      |                     |            |
  |         |           |                     | Any of:    |
  |         |           |                     |  Entropy   |
  |         |           |                     |  Byteclass |
  |_________|___________|                     |  Magnitude |
  |                     |                     |  ...       |
  |  Tags & Attributes  |                     |            |
  |   (of selection)    |                     |            |
  |                     |                     |            |
  L_____________________._____________________.____________,

```

#### Screenshot:
<div align="center">
<img id="ofrak-animation" src="assets/ofrak_gui_1.png" style="max-width:1000px;width:100%">
</div>

## Getting Started
See the [Getting Started guide](./getting-started.md) for examples on how to use OFRAK.

## Licensing
The code in this repository comes with an [OFRAK Community License](https://github.com/redballoonsecurity/ofrak/blob/master/LICENSE), which is intended for educational uses, personal development, or just having fun.

Users interested in using OFRAK for commercial purposes can request the Pro or Enterprise License. See [OFRAK Licensing](https://ofrak.com/license/) for more information.

## Support
Please contact [ofrak@redballoonsecurity.com](mailto:ofrak@redballoonsecurity.com), or write to us on [the OFRAK Slack](https://join.slack.com/t/ofrak/shared_invite/zt-1jku9h6r5-mY7CeeZ4AT8JVmu5YWw2Qg) with any questions or issues regarding OFRAK. We look forward to getting your feedback! Sign up for the [OFRAK Mailing List](https://ofrak.com/sign-up) to receive monthly updates about OFRAK code improvements and new features.
