# PyGhidra Backend
Unlike the `ofrak_ghidra` module, `ofrak_pyghidra` does not require a server running to make calls to. It uses path to your Ghidra installation to ... 

## Install

=== "Native"

    1.  Create a virtual environment to which you will install code:
        ```
        % python3 -m venv venv
        % source venv/bin/activate
        ```
    1. Install `ofrak` and its dependencies.
    1. Run `make {install, develop}` inside of the [`ofrak_cached_disassembly/`](https://github.com/redballoonsecurity/ofrak/tree/master/disassemblers/ofrak_cached_disassembly) directory.
    1. Run `make {install, develop}` inside of the [`ofrak_pyghidra/`](https://github.com/redballoonsecurity/ofrak/tree/master/disassemblers/ofrak_pyghidra) directory.
    1. Set the `GHIDRA_INSTALL_DIR` environement variable with `export GHIDRA_INSTALL_DIR=/install/ghidra_11.3.2_PUBLIC/`
    1. Install pyghidra `cd ${GHIDRA_INSTALL_DIR}/Ghidra/Features/PyGhidra/pypkg/ && python3 -m pip install -e .`

    Note: If you are using and Arm processor, you might need to compile the [native binaries](https://htmlpreview.github.io/?https://github.com/NationalSecurityAgency/ghidra/blob/Ghidra_10.1_build/GhidraDocs/InstallationGuide.html#Build) for decompilation to work 
=== "Docker"

    Follow the instructions in the [OFRAK environment setup guide](../../environment-setup.html) to build a Docker container with PyGhidra. Ghidra and PyGhidra will be automatically installed if the `disassemblers/ofrak_ghidra` package is included in the Docker build's config file.
    An example configuration is provided in the `ofrak-pyghidra.yml`

## Usage
Once installed you can import `ofrak_pyghidra` into any script 

```python
import ofrak_pyghidra

ofrak = OFRAK(logging.INFO)
ofrak.discover(ofrak_pyghidra)
```
or open the gui with `ofrak gui --backend pyghidra` to unpack and anlyze a binary.

If the resource is correctly tagged as a Program or IHex, it should automatically be tagged as `PyGhidraProject` when identified if the `ofrak_pyghidra` module is discovered.


## PyGhidra Analysis
The analysis will disassemble and decompile the entire program the first time you run analysis. The results will be cached in a cached analysis store, so the next time you disassemble (unpack) or decompile (analyze) the data will be available immediately. To save the analysis for faster loading times, see the Cached Analysis section below.

### PyGhidra auto-analysis
ofrak_pyghidra will automatically analyze program attributes for Elf, Ihex, and Pe file formats. 

```python
resource = await ofrak_context.create_root_resource_from_file("my_file.elf")

await resource.unpack_recursively()
await resource.analyze_recursively()
```

### PyGhidra manual analysis
If your file is not one of the auto analysis formats, you will need to manually tag the resource as a `Program` and add `ProgramAtributes`.

```python
resource = await ofrak_context.create_root_resource_from_file(file_path)
resource.add_tag(Program)
program_attributes = ProgramAttributes(
    InstructionSet.ARM,
    bit_width=BitWidth.BIT_32,
    endianness=Endianness.LITTLE_ENDIAN,
    sub_isa=None,
    processor=None,
)

resource.add_attributes(program_attributes)
await resource.save()
```

### Cached analysis
PyGhidra uses the cached disassembly module to store the results of any disassembly and decompilation for later use so there is no need to run the analysis again. 

#### Saving cached analysis
To save a cache to a json file

1) With the ofrak_pyghidra module

```bash
python -m ofrak_pyghidra analyze --infile my_file.elf --outfile cache_file.json --language ARM:LE:32:v7 --decompile
```

See `python3 -m ofrak_pyghidra analyze -h` for more details on usage

2) Inside of a script using the `unpack` function
This will run the unpackers, and also decompile if the flag is set to True

```python
import json
from ofrak_pyghidra.standalone.pyghidra_analysis import unpack

res = unpack(resource_file, decompile, language)
with open("cache_file.json", "w") as fh:
    json.dump(res, fh, indent=4)
```

3) Inside of a script after running the analysis manually

```python
root_resource = await ofrak_context.create_root_resource_from_file(
    "my_file.elf"
)

# Run some analysis here

injector = ofrak_context.injector
cached_store = await injector.get_instance(CachedAnalysisStore)
analysis = cached_store.get_analysis(root_resource.get_id())

with open("cache_file.json", "w") as fh:
    json.dump(analysis, fh, indent=4)
```

#### Loading cached analysis
Load an analysis json file with `PyGhidraCachedAnalysisAnalyzer`

```python
await resource.run(
    PyGhidraCachedAnalysisAnalyzer,
    config=CachedAnalysisAnalyzerConfig(
        filename="cache_file.json")
)
```