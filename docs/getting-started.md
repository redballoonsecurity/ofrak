# Getting Started

Welcome to OFRAK! This guid will help you get up and running quickly.

## Quick Start

If you just cannot wait to try out OFRAK, you can install it from PyPI and get working immediately:

```bash
# 1. Install OFRAK
pip install ofrak

# 2. Accept the community license
ofrak license --community --i-agree

# 3. Unpack a file and view it in the GUI
ofrak unpack --exclude-components-missing-dependencies --recursive --gui <path-to-file>
```

The GUI will open at <http://localhost:8080> showing your unpacked file.

To try out one of the disassembler backends, run
```bash
# Install OFRAK's angr and capstone modules
pip install ofrak-angr ofrak-capstone

# Make sure community license is accepted
ofrak license --community --i-agree

# Unpack a file and view it in the GUI
ofrak unpack -x -r --gui <path-to-executable>
```

Happy reverse engineering! Run `ofrak --help` (or read the docs) if you need help.

## Installation

OFRAK can be installed in multiple ways depending on your needs:

- **[From PyPI](install/pypi.md)** - Quick installation via pip
- **[Using Docker](install/docker.md)** - Pre-configured environment with all dependencies
- **[From Source](install/source.md)** - For development and contribution

See our [Installation Guide](install/index.md) to help you choose the right method.

## GUI

OFRAK comes with a web-based GUI for visualizing and manipulating binaries.
After installation, run `ofrak gui`:

```bash
$ ofrak gui
Using OFRAK Community License.
GUI is being served on http://127.0.0.1:8080/
```

To access the GUI, navigate to <http://localhost:8080> (or the port specified with `-p/--port` or `-gp/--gui-port`) and start by dropping anything you'd like into it!
See [OFRAK GUI Docs](user-guide/gui/minimap.md) for more info on using the GUI.

The GUI can also be used with the OFRAK CLI (via the `--gui` flag) and is typically running by default in the OFRAK Docker images.

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
