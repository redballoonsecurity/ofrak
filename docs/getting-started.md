# Getting Started

## Quick Start - Unpack a firmware file and display it in the GUI

!!! warning
    OFRAK is a Python library supporting Python3.7 and up. First and foremost, make sure your Python and pip installations are for Python3.7+! Python 3.8 is recommended, as this is the version we primarily test OFRAK with, and some packages (for example, ofrak-angr) require Python >=3.8.

```bash
pip install ofrak
ofrak unpack -x -r --gui <path-to-file>

```

This will install OFRAK, run OFRAK to unpack a target file, then open it in the GUI.

- The `-x` (`--exclude-components-missing-dependencies`) flag tells OFRAK to exclude components which are missing dependencies, which makes installation much easier at the price of missing out on support for some file types.
See [Environment Setup](environment-setup.md#handling-non-python-dependencies) for more information.

- The `--gui` flag starts up an OFRAK GUI server after file is unpacked, and tries to open it in your browser.
The GUI will display the unpacked structure of the file, as OFRAK understands it.

- The `-r` (`--recursive`) flag tells OFRAK to "recursively" unpack the target, until OFRAK can't subdivide its components any further.

See `ofrak unpack --help` for other options and more information on each flag.

### Disassembling with OFRAK

OFRAK does not do its own disassembly, and instead re-uses several existing, capable tools.
To quickly start disassembling using OFRAK, we recommend installing two more OFRAK Python packages:

```bash
pip install ofrak_angr ofrak_capstone
```

These packages leverage [angr](https://angr.io/) and [capstone](https://www.capstone-engine.org/) to disassemble machine code. 
Both are needed, as they work together - angr tells OFRAK information about the higher-level structures (such as where functions are) and capstone disassembles individual chunks of machine code.
After running the above `pip install` command, modify the `ofrak unpack` command from earlier to include the option `--backend angr`:

```shell
ofrak unpack -x --gui -r --backend angr <path-to-file>

```

This will get OFRAK to disassemble any code it recognizes in the files it unpacks.
A word of warning though - binaries don't have to get very large before disassembling starts to take a long time!
This problem gets exponentially worse if you are unpacking a packed filesystem with potentially many executables.
If that is the case, consider removing the `-r` flag so that OFRAK only unpacks the top level; once the resource is opened in the GUI, you can select specific children to unpack.


## GUI

OFRAK comes with a web-based GUI frontend for visualizing and manipulating binary targets. The OFRAK GUI runs by default in most of the OFRAK images, including the tutorial image. (Note that for now, the frontend is only built in the `ofrak_ghidra` and `ofrak_binary_ninja` analyzer backend configurations.)

To access the GUI, navigate to <http://localhost:8080> and start by dropping anything you'd like into it!


## Building from Docker

OFRAK also has a Docker build system. 
This has the advantage of producing a consistent environment with all dependencies installed, but requires a Docker installation and running the build procedure.
Check out the [Docker build documentation](environment-setup.md#docker) if you are interested.


## Tutorial

A great way to get started with OFRAK is to go through the interactive tutorial.

Run it with the following commands:

```shell
make tutorial-image  # create the Docker image for the tutorial
make tutorial-run
```

It takes a minute for the notebook to start up. Once running, you can access the tutorial from [localhost:8888](http://localhost:8888) with your web browser. Have fun!


## Docs

The official documentation for the most up-to-date OFRAK lives at <https://ofrak.com/docs/>.

If you would like to generate the docs yourself for offline viewing, follow the instructions in the [`docs/README.md`](https://github.com/redballoonsecurity/ofrak/blob/master/docs/README.md) file.

## Guides and examples

Once you've completed the tutorial, you'll be interested in the following resources (which you can see on the left of this page):

- More details about how OFRAK works and how to use it: `User Guide` and `Contributor Guide`;
- References: `Examples`, covering common tasks you might want to perform with OFRAK, and the `Code Reference`.

## Frequently Asked Questions (FAQ)

_Why do my CodeRegions not have any code?_

- You probably forgot to discover the analysis/disassembler backend you intended to use.
- When **not** using the Ghidra analysis backend you will also need to discover the capstone components.
- Check out the [Ghidra Backend User Guide](user-guide/disassembler-backends/ghidra.md) and [Binary Ninja Backend User Guides](user-guide/disassembler-backends/binary_ninja.md).

_I ran a modifier and flushed the resource. The bytes did change, but my view is reporting the same values. Why?_

- The bytes may have changed, but the analysis that depends on those bytes may not have been forced to re-run. You can force this analysis to update by re-running `await resource.view_as` if you want to get an updated view after modifying data the view depends on.

<div align="right">
<img src="./assets/square_01.png" width="125" height="125">
</div>
