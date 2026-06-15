# Cached Disassembly
The `ofrak_cached_disassembly` module allows you to load a previously saved disassembly and decompilation analysis at a later time. This avoids performing the analysis more than once. 

## Usage

Discover the cached disassembly module with:

```python
ofrak = OFRAK(logging.INFO)
ofrak.discover(ofrak_cached_disassembly)
```

Note: `ofrak_pyghidra` is currently the only analysis backend that supports storing a disassembly file for loading with `ofrak_cached_disassembly`.

### Saving Cached Analysis
To save a cache to a JSON file, see the `ofrak_pyghidra` ["Saving Cached Analysis"](./pyghidra.md#saving-cached-analysis) section of the documentation.

### Loading Cached Analysis

To load a saved JSON cache file, run the `CachedAnalysisAnalyzer`:

```python
await resource.run(
    CachedAnalysisAnalyzer,
    config=CachedAnalysisAnalyzerConfig(
        filename="cache_file.json"
    ),
)
```

Once the cached analysis is loaded, you can run `unpack_recursively` and `analyze_recursively` to create the child resources.

## Gotchas
The `ofrak_cached_disassembly` module is an OFRAK backend and cannot be used concurrently with other OFRAK backends. The following code will not work, since you can only use one backend at a time.

```python
ofrak.discover(ofrak_cached_disassembly)
ofrak.discover(ofrak_pyghidra)
```

<div align="right">
<img src="../../assets/square_01.png" width="125" height="125">
</div>
