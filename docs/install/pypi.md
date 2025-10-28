# Install from PyPI

Install OFRAK quickly using pip for the simplest setup.

## Prerequisites

- Python 3.9+ and pip
- cmake and libmagic (macOS only - install via `brew install cmake libmagic`)

## Quick Install

!!! tip "Use virtual environment"
    We strongly recommend installing OFRAK using a Python virtual environment.
    For example, to use [venv](https://docs.python.org/3/library/venv.html):
    ```bash
    $ python3 -m venv venv
    $ source venv/bin/activate
    ```

```bash
pip install ofrak
```

## Verify Installation
Activate an [OFRAK License](../license.md). For example, to use the OFRAK Community License:
```bash
$ ofrak license --community --i-agree
```

See `ofrak license --help` for more license options.

Once the license is installed, this command will list all installed OFRAK modules and components:

```bash
ofrak list
```

## Installing Disassembler Backend

### angr + Capstone (Recommended for beginners)

```bash
pip install ofrak_angr ofrak_capstone
```

These work together: angr identifies functions, capstone disassembles code.

### Ghidra

```bash
pip install ofrak_ghidra
```

Requires Ghidra installed separately. See [Ghidra Backend Guide](../user-guide/disassembler-backends/ghidra.md).

### Binary Ninja

```bash
pip install ofrak_binary_ninja
```

Requires Binary Ninja license. See [Binary Ninja Backend Guide](../user-guide/disassembler-backends/binary_ninja.md).

## Common Issues

### Python Version Errors

**Symptoms**: Import errors, package installation failures.

**Solution**: Use Python 3.9+ for full compatibility:
```bash
python3.9 -m pip install ofrak
```

### Missing System Dependencies

**Symptoms**: Runtime errors about missing tools (e.g., "pigz not found").

**Solution**: Use `ofrak deps` to identify and install (see above).

### Permission Errors

**Solution**: Use virtual environment or `--user` flag:
```bash
pip install --user ofrak
```

<div align="right">
<img src="../assets/square_05.png" width="125" height="125">
</div>
