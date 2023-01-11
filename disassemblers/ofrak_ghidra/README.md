# OFRAK Ghidra Components
This package contains OFRAK components that use Ghidra as the analysis engine.

# Prerequisites
This package requires:
- a valid OFRAK installation
- a valid installation of Ghidra

# Docker
Follow the instructions in the [OFRAK environment setup guide](https://ofrak.com/docs/environment-setup.html) to build a Docker container with Ghidra.

# MacOS
1. Ensure that you have a valid installation of Ghidra
2.  Create a virtual environment to which you will install code:
    ```
    % python3 -m venv venv
    % source venv/bin/activate
    ```
3. Install `ofrak` and its dependencies.
4. Finally, run `make {install, develop}` to install `ofrak_ghidra`.

## Testing
This package maintains 100% test coverage of functions.
