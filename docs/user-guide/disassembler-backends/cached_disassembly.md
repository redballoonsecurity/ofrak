# Cached Disassembly
The ofrak_cached_disassembly module allows you to load a previously stored disassembly/ decompilation for loading at a later time so the analysis doesn't need to be performed more than once. 

## Usage

Discover the cached disassembly module with

```python
    ofrak = OFRAK(logging.INFO)
    ofrak.discover(ofrak_cached_disassembly)
```

Note: ofrak_pyghidra is the only backend that currently allows you to store a disassembly file for loading with ofrak_cached_disassembly.

### Saving Cached Analysis
To save a cache to a json file see the [ofrak_pyghidra](./pyghidra.md) Saving cached analysis section.

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

Once the cached analysis is loaded, you can run unpack_recursively and anaylze_recursively to create the child resources.

## Gotchas
The ofrak_cached_disassembly module is an ofrak backend and cannot be used with the other ofrak backends. The following code would not be allowed since you can only use one backend at a time.

```python
ofrak.discover(ofrak_cached_disassembly)
ofrak.discover(ofrak_pyghidra)
```
