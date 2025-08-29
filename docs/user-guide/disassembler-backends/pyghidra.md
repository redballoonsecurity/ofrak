# PyGhidra Backend
Use the `ofrak_pyghidra` module to disassemble and decompile binaries using Ghidra via the PyGhidra Python bindings. Unlike the `ofrak_ghidra` module, `ofrak_pyghidra` does not require a Ghidra server. Instead, it runs Ghidra in headless mode to analyze files.

## Install

=== "Native"

    1.  Create a virtual environment to which you will install code:
        ```
        % python3 -m venv venv
        % source venv/bin/activate
        ```
    1. Install `ofrak` and its dependencies.
    1. Set the `GHIDRA_INSTALL_DIR` environment variable with `export GHIDRA_INSTALL_DIR=/install/ghidra_11.3.2_PUBLIC/`, substituting in your actual Ghidra install path.
    1. Install PyGhidra with: `cd ${GHIDRA_INSTALL_DIR}/Ghidra/Features/PyGhidra/pypkg/ && python3 -m pip install -e .`
    1. Run `make install` or `make develop` inside of the [`ofrak_cached_disassembly/`](https://github.com/redballoonsecurity/ofrak/tree/master/disassemblers/ofrak_cached_disassembly) directory.
    1. Run `make install` or `make develop` inside of the [`ofrak_pyghidra/`](https://github.com/redballoonsecurity/ofrak/tree/master/disassemblers/ofrak_pyghidra) directory.

    Note: If you are using an ARM processor, you might need to compile the [native binaries](https://htmlpreview.github.io/?https://github.com/NationalSecurityAgency/ghidra/blob/Ghidra_10.1_build/GhidraDocs/InstallationGuide.html#Build) for decompilation to work.
=== "Docker"

    Follow the instructions in the [OFRAK environment setup guide](../../environment-setup.md) to build a Docker container with PyGhidra. Ghidra and PyGhidra will be automatically installed if the `disassemblers/ofrak_ghidra` package is included in the YAML configuration file.
    An example configuration is provided in `ofrak-pyghidra.yml`.

## Usage
Once installed, you can import `ofrak_pyghidra` into any script, as you would with the other analysis back ends.  

```python
import ofrak_pyghidra

ofrak = OFRAK(logging.INFO)
ofrak.discover(ofrak_pyghidra)
```
You can also open the GUI with `ofrak gui --backend pyghidra` to unpack and analyze a binary.

If the resource is correctly tagged as a `Program` or `IHex`, it should automatically be tagged as `PyGhidraProject` when identified, if the `ofrak_pyghidra` module is discovered.


## PyGhidra Analysis
The first time you run the analysis, it will disassemble and decompile the entire program. The results will be cached in a cached analysis store, so the next time you disassemble (unpack) or decompile (analyze), the data will be available immediately. To save the analysis for faster loading times, see the [Cached Analysis](#cached-analysis) section below.

### PyGhidra auto-analysis
`ofrak_pyghidra` will automatically analyze program attributes for `Elf`, `Ihex`, and `Pe` file formats. 

```python
resource = await ofrak_context.create_root_resource_from_file("my_file.elf")

await resource.unpack_recursively()
await resource.analyze_recursively()
```

### PyGhidra manual analysis
If your file is not in one of the formats that OFRAK can analyze automatically, you will need to manually tag the resource as a `Program` and add `ProgramAttributes`.

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

resource.identify()
```

You will need to add the `CodeRegion` view manually so that OFRAK knows where to unpack code in the binary.

```python
new_length = await resource.get_data_length()
await resource.create_child_from_view(
    CodeRegion(
        virtual_address=0,
        size=new_length,
    ),
    Range.from_size(0, new_length)
)
await resource.save()
```


### Cached analysis
PyGhidra can store the results of any disassembly and decompilation for later use. 

#### Saving cached analysis
To save a cache to a JSON file:

1. With the `ofrak_pyghidra` module.

    ```bash
    python -m ofrak_pyghidra analyze --infile my_file.elf --outfile cache_file.json --language ARM:LE:32:v7 --decompile
    ```

    See `python3 -m ofrak_pyghidra analyze -h` for more details on usage.

1. In a script using the `unpack` function.

    ```python
    import json
    from ofrak_pyghidra.standalone.pyghidra_analysis import unpack

    decompile = True  # decompile in addition to disassembling
    language = "..."
    res = unpack(resource_file, decompile, language)
    with open("cache_file.json", "w") as fh:
        json.dump(res, fh, indent=4)
    ```

1. In a script after running the analysis manually.

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
To load an analysis JSON file, see the [`Cached Disassembly Backend`](./cached_disassembly.md).
