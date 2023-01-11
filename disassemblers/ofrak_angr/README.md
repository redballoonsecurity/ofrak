# OFRAK angr Components
Use [angr](https://angr.io/) to unpack Code Regions and Complex Blocks.

Once angr's CFG is processed into OFRAK, the hierarchy of the non-overlapping packing structure of an executable is expected to look like this:
  - Code Regions
    - Complex Blocks
      - Basic Blocks
      - DataWords

OFRAK works on packing structures of data on real memory addresses. angr reflects memory addresses as it appears to a program running inside of it. As such, certain tranformations have to be made from angr's analysis before exporting to OFRAK, including:
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


# Prerequisites
## Docker
The following command will build an OFRAK with angr capabilities.
```bash
python3 build_image.py --config ofrak-angr.yml --base --finish
```

## MacOS
1. Create a virtual environment to which you will install code:
    ```
    % python3 -m venv venv
    % source venv/bin/activate
    ```
2. Install `ofrak` and its dependencies.
3. Finally, run `make {install, develop, test}`

## Testing
This package maintains 100% test coverage of functions.
