# OFRAK CLI

## Handling Missing Dependencies

OFRAK integrates many external tools. Not all can be installed via pip.

### Option 1: Exclude Missing Dependencies

Use the `--exclude-components-missing-dependencies, -x` flag to skip components with missing dependencies:

```bash
ofrak unpack --exclude-components-missing-dependencies <file>
```

**Note**: This prevents errors but means OFRAK can't use those components.
For example, without `apktool`, APK files can't be unpacked.

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
