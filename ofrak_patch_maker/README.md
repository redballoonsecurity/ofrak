# OFRAK
OFRAK (Open Firmware Reverse Analysis Konsole) is a binary analysis and modification platform that combines the ability to unpack, analyze, modify, and repack binaries.


# Package: ofrak_patch_maker

```
OFRAK
└───ofrak
└───ofrak_type
└───ofrak_io
└───ofrak_patch_maker  <-- //YOU ARE HERE//
│   └───binary_parser   // Interface and implementations for class parsing symbols & sections from a binary
│   └───toolchain       // Interface and implementations for build toolchains
│   └───model.py
│   └───patch_maker.py
└───ofrak_tutorial
```

This package contains the OFRAK PatchMaker, a powerful tool for applying source-code patches to binary files.

PatchMaker is a Python package for building code patch blobs from source and injecting them into an executable OFRAK
resource. Once a patch is applied to a Resource, it may be re-packed with OFRAK the same way as if only a string
modification were applied.

PatchMaker takes additional steps beyond the typical C software build process to ensure that new code and data, provided
in C/asm source or binary form, land where they are supposed to and that linking against existing code and data in the
target binary is easy.

Think of it as a way to compile custom code using the binary-under-analysis as a library. Normally a loader is
responsible for mapping external symbols correctly into the loaded executable's memory space. With PatchMaker the
process is inverted: once the patch is compiled, it can be injected into the host binary with the patch's external
symbols correctly linked to the host's internal symbols, without involving a loader.

For more information, check the [user guide in the OFRAK docs](https://ofrak.com/docs/user-guide/patch-maker/user-guide.html)
as well as the [code references for PatchMaker](https://ofrak.com/docs/reference/ofrak_patch_maker/patch_maker.html) and related classes.

## Dependencies
This Python package only includes the Python code for the PatchMaker and does not include any of the 
toolchains which the PatchMaker utilizes! These would have to be
installed individually and added to a `toolchain.conf`, which by default is placed in `/etc`.
An example of the `toolchain.conf` can be found [here](https://github.com/redballoonsecurity/ofrak/blob/master/ofrak_patch_maker/toolchain.conf),
and examples of how to install the toolchains can be found [here](https://github.com/redballoonsecurity/ofrak/blob/master/ofrak_patch_maker/Dockerstub).

## Testing
This package maintains 100% test coverage of functions.

The tests for `ofrak_patch_maker` are not distributed with this package.
If you wish to run the tests, download the [OFRAK source code](https://github.com/redballoonsecurity/ofrak) and install/run the tests from there.


## License
The code in this repository comes with an [OFRAK Community License](https://github.com/redballoonsecurity/ofrak/blob/master/LICENSE), which is intended for educational uses, personal development, or just having fun.

Users interested in using OFRAK for commercial purposes can request the Pro or Enterprise License. See [OFRAK Licensing](https://ofrak.com/license/) for more information.

## Documentation
OFRAK has general documentation and API documentation, which can be viewed at <https://ofrak.com/docs>.
