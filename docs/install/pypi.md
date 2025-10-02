# Install from PyPI

Install OFRAK quickly using pip for the simplest setup.

## Prerequisites

- Python 3.9+ and pip

## Quick Install

```bash
pip install ofrak
```

This installs the core `ofrak` package and `ofrak_patch_maker` along with all Python dependencies.

## Verify Installation



```mermaid

```

```bash
ofrak list
```

This lists all installed OFRAK modules and components.

## What's Included

The PyPI installation provides:
-  OFRAK core functionality
-  Patch maker
- L Disassembler backends (require separate installation)
- L Some analysis components (optional)

## Installing Disassemblers

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

## Handling Missing Dependencies

OFRAK integrates many external tools. Not all can be installed via pip.

### Option 1: Exclude Missing Dependencies

Use the `-x` flag to skip components with missing dependencies:

```bash
ofrak unpack -x <file>
```

Or in Python:

```python
from ofrak import OFRAK

ofrak = OFRAK(
    exclude_components_missing_dependencies=True
)
```

**Note**: This prevents errors but means OFRAK can't use those components. For example, without `pigz`, gzip files can't be processed.

### Option 2: Install Missing Dependencies

Check what's missing:

```bash
ofrak deps --missing-only
```

Install via package manager:

```bash
# Ubuntu/Debian
ofrak deps --packages-for apt | xargs sudo apt install -y

# macOS
ofrak deps --packages-for brew | xargs brew install
```

## Common Issues

### Python Version Errors

**Symptoms**: Import errors, package installation failures

**Solution**: Use Python 3.8+ for full compatibility:
```bash
python3.9 -m pip install ofrak
```

### Missing System Dependencies

**Symptoms**: Runtime errors about missing tools (e.g., "pigz not found")

**Solution**: Use `ofrak deps` to identify and install (see above)

### Permission Errors

**Solution**: Use virtual environment or `--user` flag:
```bash
pip install --user ofrak
```

## Next Steps

- [Accept OFRAK License](../getting-started.md#quick-start) - Required before first use
- [Quick Start Guide](../getting-started.md#quick-start) - Unpack your first file
- [Getting Started](../getting-started.md) - Tutorials and examples
- [Troubleshooting](../environment-setup.md#troubleshooting-common-installation-issues) - Common issues and solutions
