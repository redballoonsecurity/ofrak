# Binary Ninja Backend

## Install

Binary Ninja is not distributed with OFRAK. **You need to have a valid Binary Ninja license to use OFRAK Binary Ninja.** You can run OFRAK Binary Ninja natively with a valid **commercial** licence, and in a Docker container with a valid **headless** license.

The recommended Binary Ninja version to use with OFRAK is 3.2.3814. If you are running OFRAK outside of the Docker image, you can switch to this version of Binary Ninja using the [Binary Ninja version switcher](https://github.com/Vector35/binaryninja-api/blob/dev/python/examples/version_switcher.py).

=== "Native"

    You need to have Binary Ninja installed along with a valid **commercial** Binary Ninja license to run OFRAK Binary Ninja natively. 

    1. Create a virtual environment to which you will install code:
        ```
        % python3 -m venv venv
        % source venv/bin/activate
        ```
    1. Install `ofrak` and its dependencies.
    1. Run `make {install, develop}` inside of the ['ofrak_binary_ninja/'](https://github.com/redballoonsecurity/ofrak/tree/master/disassemblers/ofrak_binary_ninja) directory to install OFRAK Binary Ninja.
    1. Next, install the Binary Ninja Python APIs in your virtual environment
        ```python
        % python3 "/Applications/Binary Ninja.app/Contents/Resources/scripts/install_api.py" -v
        ```

=== "Docker"

    You need to have a valid **headless** Binary Ninja license to build and run the Docker image. [Read about the environment setup](../../environment-setup.md#binary-ninja) for more details.

    To build the image, the license should be placed in the project's root directory and named `license.dat`. The serial number needs to be extracted from that file into a file named `serial.txt`. This can be done with the following command:

    ```bash
    python3 \
      -c 'import json, sys; print(json.load(sys.stdin)[0]["serial"])' \
      < license.dat \
      > serial.txt
    ```

    The command `python3 build_image.py --config ofrak-binary-ninja.yml --base --finish` will build an image using Docker BuildKit secrets so that neither the license nor serial number are exposed in the built Docker image. BuildKit is required for the build to succeed!

    The Docker container should be run with the same license file from the installation step. The license can then be mounted into the Docker container at location `/root/.binaryninja/license.dat` by adding the following arguments to the `docker run` command:

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
from ofrak import OFRAK
import ofrak_binary_ninja
import ofrak_capstone

ofrak = OFRAK()
ofrak.discover(ofrak_binary_ninja)
ofrak.discover(ofrak_capstone)
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
import logging
from ofrak import OFRAK
from ofrak import OFRAKContext
import ofrak_capstone
import ofrak_binary_ninja
from ofrak_binary_ninja.components.binary_ninja_analyzer import (
    BinaryNinjaAnalyzerConfig,
    BinaryNinjaAnalyzer,
)

async def main(ofrak_context: OFRAKContext):
    resource = await ofrak_context.create_root_resource_from_file(<file_path>)
    binary_ninja_config = BinaryNinjaAnalyzerConfig(<bndb_file_path>)
    await resource.run(BinaryNinjaAnalyzer, binary_ninja_config)


if __name__ == "__main__":
    ofrak = OFRAK(logging.INFO)
    ofrak.discover(ofrak_binary_ninja)
    ofrak.discover(ofrak_capstone)
    ofrak.run(main)
```

## Documentation

[Binary Ninja User Documentation](https://docs.binary.ninja/index.html)

[Binary Ninja Python API code](https://github.com/Vector35/binaryninja-api/tree/dev/python)

## Troubleshooting

You can test python code in the interactive python console available in the Binary Ninja desktop application. Enable it with `View -> Native Docks -> Show Python Console` (on Mac).
