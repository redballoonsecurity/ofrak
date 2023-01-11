# OFRAK
OFRAK (Open Firmware Reverse Analysis Konsole) is a binary analysis and modification platform that combines the ability to unpack, analyze, modify, and repack binaries.


# Package: ofrak_capstone

```
OFRAK
└───ofrak
│   └───disassemblers
│       └───ofrak_angr
│       └───ofrak_binary_ninja
│       └───ofrak_capstone  <-- //YOU ARE HERE//
│       |   └───components.py
│       |   └───disassembler_service_capstone.py
│       └───ofrak_ghidra
└───ofrak_type
└───ofrak_io
└───ofrak_patch_maker
└───ofrak_tutorial
``` 

This package contains OFRAK components utilizing the [Capstone](https://www.capstone-engine.org/) disassembler:
* `CapstoneBasicBlockUnpacker` for unpacking `BasicBlock`s into their constituent `Instructions`
* `CapstoneInstructionAnalyzer` for re-analyzing an `Instruction` if its data is changed
* `CapstoneInstructionRegisterUsageAnalyzer` for determining which register an `Instruction` reads/writes

Unlike the other "disassembler" packages, this does not include a `CodeRegionUnpacker` or `ComplexBlockUnpacker`
to deconstruct a section of code into functions and basic blocks. It is useful for applications which:
* Work only with individual instructions or basic blocks.
* Also use one of the other packages under `disassemblers`, which can handle the higher-level structures and leave the basic blocks to be handled by `ofrak_capstone`.

After installing the package, it can be used in an OFRAK script by adding the following to the setup step:

```python
import ofrak_capstone
...
ofrak = OFRAK()
... # Other setup steps
ofrak.discover(ofrak_capstone)
```

## Testing
The tests for `ofrak_capstone`  require the tests to be installed for the core OFRAK module. These must
first be installed after downloading the [OFRAK source code](https://github.com/redballoonsecurity/ofrak).

Then, the `ofrak_capstone` tests can be run with:

```python
pytest --pyargs ofrak_capstone_test

```

## Testing
This package maintains 100% test coverage of functions.

## License
The code in this repository comes with an [OFRAK Community License](https://github.com/redballoonsecurity/ofrak/blob/master/LICENSE), which is intended for educational uses, personal development, or just having fun.

Users interested in using OFRAK for commercial purposes can request the Pro or Enterprise License. See [OFRAK Licensing](https://ofrak.com/license/) for more information.

## Documentation
OFRAK has general documentation and API documentation, which can be viewed at <https://ofrak.com/docs>.
