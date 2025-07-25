# Cached Disassembly

## Usage

discover with

```python
    ofrak = OFRAK(logging.INFO)
    ofrak.discover(ofrak_cached_disassembly)
```

Note: ofrak_pyghidra is the only backend that currently uses the ofrak_cached_disassembly module for storing disassembly 

### Saving Cached Analysis
To save a cache to a json file

1) With the ofrak_pyghidra module

```bash
python -m ofrak_pyghidra analyze --infile /ofrak_uboot/assets/u-boot.bin --outfile /ofrak_uboot/assets/uboot.json --language ARM:LE:32:v7 --decompile
```

See `python3 -m ofrak_pyghidra analyze -h` for more details on usage

2) Inside of a script using the `unpack` function
This will run the unpackers, also decompile if the flag is set to True

```python
import json
from ofrak_pyghidra.standalone.pyghidra_analysis import unpack

res = unpack(args.infile, args.decompile, args.language)
with open(args.outfile, "w") as fh:
    json.dump(res, fh, indent=4)
```

3) Inside of a script after running the analysis manually

```python
root_resource = await ofrak_context.create_root_resource_from_file(
    os.path.join(os.path.dirname(__file__), "assets/hello.x64.elf")
)

# Run some analysis here

injector = ofrak_context.injector
cached_store = await injector.get_instance(CachedAnalysisStore)
analysis = cached_store.get_analysis(root_resource.get_id())

with open(args.outfile, "w") as fh:
    json.dump(analysis, fh, indent=4)
```

### Loading Cached Analysis

To load a saved json cache file, run the `CachedAnalysisAnalyzer`

```python
await resource.run(
    CachedAnalysisAnalyzer,
    config=CachedAnalysisAnalyzerConfig(
        filename="cache_file.json"
    ),
)
```



## Gotchas
The ofrak_cached_disassembly module is an ofrak backend and cannot be used with the other ofrak backends. The following code would not be allowed since you can only use one backend at a time.

```python
ofrak.discover(ofrak_cached_disassembly)
ofrak.discover(ofrak_pyghidra)
```