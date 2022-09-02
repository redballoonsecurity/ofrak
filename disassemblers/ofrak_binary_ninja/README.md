# OFRAK BinaryNinja Components
This package contains OFRAK components that use BinaryNinja as the analysis engine.

# Prerequisites
This package requires:
- a valid OFRAK installation
- a valid installation of BinaryNinja
- the BinaryNinja python APIs

## Docker
Follow the instructions in the [OFRAK environment setup guide](https://ofrak.com/docs/environment-setup.html) to install the headless version of BinaryNinja.

## MacOS
1. Ensure that you have a valid installation of BinaryNinja.
2. Create a virtual environment to which you will install code:
    ```
    % python3 -m venv venv
    % source venv/bin/activate
    ```
3. Next, install the BinaryNinja python APIs in your virtual environment
    ```python
    % python3 "/Applications/Binary Ninja.app/Contents/Resources/scripts/install_api.py" -v
    ```
3. Install `ofrak` and its dependencies.
4. Finally, run `make {install, develop}` to install `ofrak_binary_ninja`.
