# Ghidra Backend
## Install
The Ghidra backend comes pre-installed in the OFRAK Docker image.

## Start/Stop

The Ghidra server must be running before OFRAK can use Ghidra analysis.

To start the Ghidra server, users should run `python -m ofrak_ghidra.server start`.

To stop it, run `python -m ofrak_ghidra.server stop`.

## Usage
To use Ghidra, you need to discover the component at setup-time with:
```python
ofrak = OFRAK(logging.INFO)
ofrak.injector.discover(ofrak_ghidra)
```

!!! warning
    You can only use one of these analysis backends at a time (Ghidra OR Binary Ninja OR IDA) 

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
async def main(ofrak_context: OFRAKContext,):
    resource = await ofrak_context.create_root_resource_from_file(<file_path>)
    ghidra_config = GhidraProjectConfig(<gzf_file_path>)
    await resource.run(GhidraProjectAnalyzer, ghidra_config)


if __name__ == "__main__":
    ofrak = OFRAK(logging.INFO)
    ofrak.injector.discover(ofrak_ghidra)
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
this is `~/.ghidra/.ghidra_10.1.2_PUBLIC/application.log`.

You can check the log file path for your sysem by running 
`python -m ofrak_ghidra.config dump` and searching for the `log_file` setting under `ghidra_install` .

If you have doubts that the Ghidra server is running, you can run netstat in the docker container:
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
