# OFRAK
OFRAK (Open Firmware Reverse Analysis Konsole) is a binary analysis and modification platform that combines the ability to unpack, analyze, modify, and repack binaries.


# Package: ofrak_angr

```
OFRAK
└───ofrak
│   └───disassemblers
│       └───ofrak_angr  <-- //YOU ARE HERE//
│       |   └───components
│       |       └───blocks
│       |       |   └───unpackers.py
│       |       └───angr_analyzer.py
│       |       └───identifiers.py
│       └───ofrak_binary_ninja
│       └───ofrak_capstone
│       └───ofrak_ghidra
└───ofrak_type
└───ofrak_io
└───ofrak_patch_maker
└───ofrak_tutorial
``` 

This package contains OFRAK components utilizing [angr](https://angr.io/) to unpack Code Regions and Complex Blocks:
* `AngrCodeRegionUnpacker` for unpacking `CodeRegion`s into their constituent `ComplexBlock`
* `AngrComplexBlockUnpacker` unpacking `ComplexBlock`s into their constituent `BasicBlock`s
* `AngrAnalyzer` for analyzing resources with angr
* `AngrAnalysisIdentifier` for identifying resources which can be analyzed with angr


Note that this package does not contain a component to unpack `BasicBlock`s into `Instruction`s; use `ofrak_angr` in conjunction with `ofrak_capstone` if you want to unpack all the way down to the instruction level.


After installing the package, it can be used in an OFRAK script by adding the following to the setup step:

```python
import ofrak_angr
...
ofrak = OFRAK()
... # Other setup steps
ofrak.discover(ofrak_angr)
```

It can be used from the CLI by adding the `--backend angr` flag to the OFRAK CLI command.

## Testing
The tests for `ofrak_angr`  require the tests to be installed for the core OFRAK module. These must
first be installed after downloading the [OFRAK source code](https://github.com/redballoonsecurity/ofrak).

Then, the `ofrak_angr` tests can be run with:

```python
pytest --pyargs ofrak_angr_test

```

## Testing
This package maintains 100% test coverage of functions.

## License
The code in this repository comes with an [OFRAK Community License](https://github.com/redballoonsecurity/ofrak/blob/master/LICENSE), which is intended for educational uses, personal development, or just having fun.

Users interested in using OFRAK for commercial purposes can request the Pro or Enterprise License. See [OFRAK Licensing](https://ofrak.com/license/) for more information.

## Documentation
OFRAK has general documentation and API documentation, which can be viewed at <https://ofrak.com/docs>.


# Description

Once angr's CFG is processed into OFRAK, the hierarchy of the non-overlapping packing structure of an executable is expected to look like this:
  - Code Regions
    - Complex Blocks
      - Basic Blocks
      - DataWords

OFRAK works on packing structures of data on real memory addresses. angr reflects memory addresses as it appears to a program running inside of it. As such, certain transformations have to be made from angr's analysis before exporting to OFRAK, including:
  - Retrieving real memory addresses from the thumb-mode addresses returned by angr; and
  - Expanding function ranges returned by angr to include literal pools, before exporting that as part of a Complex Block

## CFG generator callback & Post-analysis hooks

### Post-analysis hooks
angr scripts can be run right after angr generates the CFG (as 'cfg') of a resource. One can load an angr python script from a file instead of writing it directly on the exec string.

```python
config = AngrAnalyzerConfig(project.analyses.CFGFast, {"normalize": True},\
        'LOGGER.info("post_cfg_analysis_hook running cfg.do_full_xrefs()"); \
        cfg.do_full_xrefs()')
```

### CFG generator callback
A different CFG analyzer may be requested, such as CFGEmulated. By default normalized CFGFast will be used.

```python
config = AngrAnalyzerConfig(project.analyses.CFGEmulated, {"normalize": True, "enable_function_hints": True})
```


## Docker
The following command will build an OFRAK with angr capabilities.
```bash
python3 build_image.py --config ofrak-angr.yml --base --finish
```
