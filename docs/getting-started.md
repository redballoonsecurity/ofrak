# Getting Started

Welcome to OFRAK! This guide will help you get up and running quickly.

## Quick Start

If you just cannot wait to try out OFRAK, you can install it from PyPI and get working immediately:

1. Install OFRAK
  ```bash
  $ pip install ofrak
  ```
2. Accept the OFRAK Community License
  ```bash
  $ ofrak license --community --i-agree
  ```
3. Unpack a file and view it in the GUI
```bash
# Unpack recursively, skipping components with missing system dependencies
$ ofrak unpack --exclude-components-missing-dependencies --recursive --gui <path-to-file>
```

The GUI will open at http://localhost:8080 showing your unpacked file.

To enable disassembly, you need to install a disassembler backend. For example, run:
```bash
$ pip install ofrak-angr ofrak-capstone
```

Then use the same unpack command as above.

Happy reverse engineering! Run `ofrak --help` for additional commands and options, or continue 
reading the documentation below.

## Installation

OFRAK can be installed in multiple ways depending on your needs:

- **[From PyPI](install/pypi.md)** - Quick installation via pip
- **[Using Docker](install/docker.md)** - Pre-configured environment with all dependencies
- **[From Source](install/source.md)** - For development and contribution

See our [Installation Guide](install/index.md) to help you choose the right method.

## CLI
See [OFRAK CLI](./ofrak-cli.md).

## GUI
See [OFRAK GUI](./ofrak-cli.md#gui).

## Tutorial

The best way to learn OFRAK is through our interactive tutorial:

### Running the Tutorial

```bash
# Build the tutorial Docker image
make tutorial-image

# Run the tutorial
make tutorial-run
```

Access the Jupyter notebook at [localhost:8888](http://localhost:8888) and work through the examples.

### What You'll Learn

- OFRAK core concepts (Resources, Components, etc.)
- Unpacking and analyzing files
- Modifying and repacking binaries
- Writing custom components
- Using different analysis backends

## Documentation Overview

The official documentation for the most up-to-date OFRAK lives at <https://ofrak.com/docs/>.

Some sections of interest include:

- **[User Guide](user-guide/)** - Detailed explanations of OFRAK concepts
- **[Examples](user-guide/examples)** - Common tasks and use cases
- **[Code Reference](reference/)** - API documentation
- **[Contributor Guide](contributor-guide/)** - For those wanting to contribute


## Frequently Asked Questions (FAQ)

_Why do my CodeRegions not have any code?_

- You probably forgot to discover the analysis/disassembler backend you intended to use. For instance, use `ofrak.discover(ofrak_ghidra)` to discover the Ghidra components.
- When **not** using the Ghidra analysis backend you will also need to discover the capstone components (`ofrak.discover(ofrak_capstone)`)
- User guides are available:
    - [Ghidra Backend User Guide](user-guide/disassembler-backends/ghidra.md)
    - [Binary Ninja Backend User Guide](user-guide/disassembler-backends/binary_ninja.md)
    - [Angr Backend User Guide](user-guide/disassembler-backends/angr.md)

_I ran a modifier and flushed the resource. The bytes did change, but my view is reporting the same values. Why?_

After modifying, you need to re-run analysis:
```python
await resource.view_as(YourViewType)  # Forces re-analysis
```

<div align="right">
<img src="./assets/square_01.png" width="125" height="125">
</div>
