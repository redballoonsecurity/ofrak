# OFRAK CLI
The OFRAK CLI is used across all OFRAK [install methods](./install/index.md) to configure OFRAK
and run the GUI.

For usage, see:
```bash
$ ofrak --help
usage: ofrak [-h] {list,deps,identify,unpack,gui,license,markup} ...

positional arguments:
  {list,deps,identify,unpack,gui,license,markup}
                        Command line utilities to use or configure OFRAK
    list                List installed OFRAK modules and/or components.
    deps                Show and check the external (non-Python) dependencies of OFRAK components. Can show the brew/apt install packages for dependencies, and
                        filter by component or package.
    identify            Identify all known structures in the binary
    unpack              Unpack all identified structures that can be unpacked with OFRAK
    gui                 Launch the OFRAK GUI server.
    license             Configure the OFRAK license
    markup              Name and comment functions from an anchor set or from portable markup

options:
  -h, --help            show this help message and exit
```

This guide explores some of these options in detail.

## Register OFRAK License
Before using OFRAK, you need to pick and register a License.

The [OFRAK Community License](license.md#ofrak-community-license-agreement) is intended for
educational uses, personal development, or just having fun. To agree with this license, run:

```bash
$ ofrak license --community --i-agree
```

To manually step through license configuration, run:
```bash
$ ofrak license
```

See [OFRAK Licensing](https://ofrak.com/license/) for more information.

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

## Markup
`ofrak markup` names and comments the functions of a binary headlessly, from an anchor set or from
portable markup exported from another build of the program, and prints which markup was applied
and which was not (see [Anchor-Based Markup & Portable RE Annotations](user-guide/advanced/portable_re_markup.md)).
It needs a backend that provides data cross-references, Ghidra or Binary Ninja:

```bash
# Name functions of build A from an anchor set, and export the result as portable markup
ofrak markup -b ghidra firmware_v1.bin --anchors anchors.yml -o firmware_v1.markup.json
# Carry that markup over to build B, and export it again for the next build
ofrak markup -b ghidra firmware_v2.bin --portable-markup firmware_v1.markup.json -o firmware_v2.markup.json
```

The import only applies a record to a function whose referenced strings it shares more than
`--similarity-threshold` of (a Jaccard similarity, 0.5 by default), and that no other function or
record matches as well. Markup is never applied to a function that already has a different name
given by an analyst; the command reports such conflicts along with the ambiguous and unmatched
markup.

## Configuring Dependencies (Quickstart)

OFRAK integrates many external tools. Not all can be installed via pip.

### Option 1: Exclude Missing Dependencies

Use the `--exclude-components-missing-dependencies, -x` flag to skip components with missing dependencies:

```bash
ofrak unpack --exclude-components-missing-dependencies <file>
```

**Note**: This prevents errors but means OFRAK can't use those components.
For example, without `apktool`, APK files can't be unpacked.

### Option 2: Install Missing Dependencies

Check what's missing, and install what you can with pacakge mangers:

```bash
ofrak deps --missing-only
ofrak deps --packages-for apt | xargs sudo apt install -y # Ubuntu/Debian
ofrak deps --packages-for brew | xargs brew install -y    # macOS
ofrak deps --packages-for choco | xargs choco install -y  # Windows 
```

## Configuring Dependencies (Detailed)

OFRAK dependencies come in three "tiers":

1. Python packages which can be installed from PyPI.
2. Packages available through standard package managers like `apt`, `brew`, or `choco`.
3. Everything else. These tools have non-standard installation steps.

### PyPI Dependencies
These are the easiest.
These are simply included in the requirements for the OFRAK Python packages which require them. 
By installing an OFRAK Python package, these dependencies will also be installed with no 
further effort required.

### Packages Available Through Standard Package Managers
See [Option 2: Install Missing Dependencies](#option-2--install-missing-dependencies).

### Dependencies with Non-Standard Installation
Running:

```shell
ofrak deps --missing-only
```
will give a printout listing each missing dependency (very often a tool required for packing or 
unpacking some type of file) and some basic info about it, including:

- Name
- Website
- Which component(s) depend on it

This is helpful in determining whether you want to skip installing one or more dependencies, 
since if you don't expect to need the component(s) requiring a dependency, you can skip it.

To see how dependencies are installed in our [Docker Images](./install/docker.md), you can inspect
the Dockerstub files in each respective OFRAK package.

<div align="right">
<img src="./assets/square_02.png" width="125" height="125">
</div>
