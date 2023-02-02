# Binary Ninja Backend

## Install

Binary Ninja is not distributed with OFRAK. **You need to have a valid headless BinaryNinja license to build and run the image.** For more details, [read about the environment setup](../environment-setup.md#binary-ninja).

The recommended BinaryNinja version to use with OFRAK is 3.2.3814. If you are running OFRAK outside of the Docker image, you can switch to this version of BinaryNinja using the [BinaryNinja version switcher](https://github.com/Vector35/binaryninja-api/blob/dev/python/examples/version_switcher.py).

To make this backend available to OFRAK, the Docker container should be run with the same license file from the installation step. The license can then be mounted into the Docker container at location `/root/.binaryninja/license.dat` by adding the following arguments to the `docker run` command:

```
--mount type=bind,source="$(pwd)"/license.dat,target=/root/.binaryninja/license.dat 
```

For example:

```bash
# This simple command...
docker run -it redballoonsecurity/ofrak/binary-ninja bash

# ...becomes the following. Notice the --mount
docker run \
  -it \
  --mount type=bind,source="$(pwd)"/license.dat,target=/root/.binaryninja/license.dat \
  redballoonsecurity/ofrak/binary-ninja \
  bash
```

## Usage

To use Binary Ninja, you need to discover the components at setup-time with:

```python
ofrak = OFRAK(logging.INFO)
ofrak.injector.discover(ofrak_binary_ninja)
```

!!! warning
    You can only use one of these analysis backends at a time (angr OR Binary Ninja OR Ghidra)

### Binary Ninja auto-analysis

Using Binary Ninja auto-analysis is transparent after the components are discovered, you don't 
have to do anything!

### Manually-analyzed program import

If Binary Ninja auto-analysis doesn't match the expected analysis of a file, you can manually process the file in the Binary Ninja desktop application and apply any manual patch of the analysis. Then export a Binary Ninja DataBase file (`.bndb`).

You will need both your original file (`<file_path>`) and the Binary Ninja DataBase (`<bndb_file_path>`) in the ofrak script.

Define a `BinaryNinjaAnalyzerConfig` and manually run the `BinaryNinjaAnalyzer`:

```python
async def main(ofrak_context: OFRAKContext,):
    resource = await ofrak_context.create_root_resource_from_file(<file_path>)
    binary_ninja_config = BinaryNinjaAnalyzerConfig(<bndb_file_path>)
    await resource.run(BinaryNinjaAnalyzer, binary_ninja_config)


if __name__ == "__main__":
    ofrak = OFRAK(logging.INFO)
    ofrak.injector.discover(ofrak_binary_ninja)
    ofrak.run(main)
```

## Documentation

[Binary Ninja User Documentation](https://docs.binary.ninja/index.html)

[Binary Ninja Python API code](https://github.com/Vector35/binaryninja-api/tree/dev/python)

## Troubleshooting

You can test python code in the interactive python console available in the Binary Ninja desktop application. Enable it with `View -> Native Docks -> Show Python Console` (on Mac).
