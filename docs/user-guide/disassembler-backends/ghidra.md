# Ghidra Backend

## Install

OFRAK supports using the Ghidra backend in two ways: natively on your host machine and inside of a Docker container.

=== "Native"

    1.  Create a virtual environment to which you will install code:
        ```
        % python3 -m venv venv
        % source venv/bin/activate
        ```
    1. Install `ofrak` and its dependencies.
    1. Run `make {install, develop}` inside of the [`ofrak_ghidra/`](https://github.com/redballoonsecurity/ofrak/tree/master/disassemblers/ofrak_ghidra) directory to install OFRAK Ghidra.
    1. Copy [`server.conf`](https://github.com/redballoonsecurity/ofrak/blob/master/disassemblers/ofrak_ghidra/server.conf) to the `server/` directory of your local Ghidra installation
    1. Run `python -m ofrak_ghidra.config dump > ofrak_ghidra.yml` to create the default YAML file
    1. Modify `ofrak_ghidra.yml` according to your local Ghidra environment. This provides OFRAK Ghidra with the paths to your Ghidra install directory and Ghidra log file as well as your Ghidra Server address and credentials.
    1. Run `python -m ofrak_ghidra.config import ofrak_ghidra.yml` so that OFRAK Ghidra can connect to the Ghidra server
    1. Run `sudo python -m ofrak_ghidra.server start`

=== "Docker"

    Follow the instructions in the [OFRAK environment setup guide](../../environment-setup.html) to build a Docker container with Ghidra. Ghidra will be automatically installed if the `disassemblers/ofrak_ghidra` package is included in the Docker build's config file.
    For example, `ofrak-ghidra.yml`:

    ```yaml
    registry: "redballoonsecurity/ofrak"
    base_image_name: "ghidra-base"
    image_name: "ghidra"
    packages_paths:
      [
        "ofrak_type",
        "ofrak_io",
        "ofrak_patch_maker",
        "ofrak_core",
        "disassemblers/ofrak_ghidra",
        "frontend",
      ]
    entrypoint: |
        nginx \
          & python3 -m ofrak_ghidra.server start \
          & python3 -m ofrak gui -H 0.0.0.0 -p 8877
    ```

## Start/Stop the Ghidra Server

The Ghidra server must be running before OFRAK can use Ghidra analysis.

To start the Ghidra server, users should run `python -m ofrak_ghidra.server start`.

To stop it, run `python -m ofrak_ghidra.server stop`.

## Usage
To use Ghidra, you need to discover the component at setup-time with:
```python
from ofrak import OFRAK
import ofrak_ghidra

ofrak = OFRAK()
ofrak.discover(ofrak_ghidra)
```

!!! warning
    You can only use one analysis backends at a time (angr OR Binary Ninja OR Ghidra) 

### Ghidra auto-analysis
Using Ghidra auto-analysis is transparent after the components are discovered, you don't have to do 
anything!

### Manually-analyzed program import
If Ghidra auto-analysis doesn't match the expected analysis of a file, you can manually process the 
file in the Ghidra desktop application and apply any manual patch of the analysis. Then export a 
Ghidra Zip File from the Ghidra desktop application. In the Ghidra CodeBrowser window, do 
`File -> Export Program...`. The default export format is `Ghidra Zip File` and produces a `.gzf` file.

You will need both your original file (`<file_path>`) and the Ghidra Zip File (`<gzf_file_path>`) in 
the ofrak script.

Define a `GhidraProjectConfig` and manually run the `GhidraProjectAnalyzer`:
```python
import logging
from ofrak import OFRAK
from ofrak import OFRAKContext
import ofrak_ghidra
from ofrak_ghidra.components.ghidra_analyzer import (
    GhidraProjectConfig,
    GhidraProjectAnalyzer
)

async def main(ofrak_context: OFRAKContext):
    resource = await ofrak_context.create_root_resource_from_file(<file_path>)
    ghidra_config = GhidraProjectConfig(<gzf_file_path>)
    await resource.run(GhidraProjectAnalyzer, ghidra_config)


if __name__ == "__main__":
    ofrak = OFRAK(logging.INFO)
    ofrak.discover(ofrak_ghidra)
    ofrak.run(main)
```

!!! warning
    This file format is not the same as the Ghidra Archive (`.gar`) file that you can export with 
    `File -> Archive Current Project...` in the Ghidra project overview window. The file you need 
    for OFRAK is a Ghidra Zip File which represent one single program, and not a full ghidra project 
    that could contain many programs.

## Documentation
[Ghidra api documentation](https://ghidra.re/ghidra_docs/api/index.html)

## Troubleshooting
If OFRAK runs in debug mode (`ofrak = OFRAK(logging.DEBUG)`), Java exceptions appear in the 
python output.

The full Ghidra logs are in Ghidra's log file. By default in the prebuilt Ghidra OFRAK Docker image,
this is `~/.ghidra/.ghidra_11.3.2_PUBLIC/application.log`.

You can check the log file path for your sysem by running 
`python -m ofrak_ghidra.config dump` and searching for the `log_file` setting under `ghidra_install` .

If you have doubts that the Ghidra server is running, you can run netstat in the Docker container:
```
apt install net-tools
netstat -tulpn
Active Internet connections (only servers)
Proto Recv-Q Send-Q Local Address           Foreign Address         State       PID/Program name
tcp        0      0 127.0.0.1:15003         0.0.0.0:*               LISTEN      3760/java
tcp        0      0 0.0.0.0:13100           0.0.0.0:*               LISTEN      3788/java
tcp        0      0 0.0.0.0:13101           0.0.0.0:*               LISTEN      3788/java
tcp        0      0 0.0.0.0:13102           0.0.0.0:*               LISTEN      3788/java
```
