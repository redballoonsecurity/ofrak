# Install from Source

Install OFRAK from source code for development or contribution.

## Prerequisites

- Python 3.9+ and pip
- Git with [Git LFS](https://git-lfs.github.com/) installed ([installation instructions](https://github.com/git-lfs/git-lfs#installing))
- make
- cmake and libmagic (macOS only - install via `brew install cmake libmagic`)

## Clone

```bash
# Clone repository
git clone https://github.com/redballoonsecurity/ofrak.git
cd ofrak

# Install Git LFS files
git lfs install
git lfs pull
```

!!! Note "OFRAK Uses Git LFS"
    If you accidentally cloned the repository before installing Git LFS,
    you can pull the LFS assets by re-running the "Install Git LFS files" step from above.

## Install Packages

### Easy Way: One Command

!!! tip "Use virtual environment"
    We strongly recommend installing OFRAK using a Python virtual environment.
    For example, to use [venv](https://docs.python.org/3/library/venv.html):
    ```bash
    $ python3 -m venv venv
    $ source venv/bin/activate
    ```

From the repository root:

```bash
make develop
```

This installs all OFRAK packages in the correct order (core packages first, then optional packages).

**Just want core packages?** Use:
```bash
make develop-core
```

## Select License

Before using OFRAK, you need to select a license. For example, to select the community license run:

```bash
ofrak license --community --i-agree
```

## Test Installation

```bash
ofrak unpack -x --gui <some-file>
```

## Troubleshooting Common Installation Issues

### Missing Git LFS Files

**Symptoms**: Binary files appear as small text pointers; test failures related to missing files; repository appears much smaller than expected.

**Cause**: Repository was cloned without Git LFS installed, so large files were downloaded as pointers instead of actual content.

**Solution**:
1. Install Git LFS: [https://git-lfs.github.com/](https://git-lfs.github.com/)
2. Initialize and pull LFS files:
   ```bash
   cd ofrak
   git lfs install
   git lfs pull
   ```
3. Verify: Binary files should now be their actual size (KB/MB range)

### Missing System Dependencies

**Symptoms**: Runtime errors about missing tools (e.g., "pigz not found"); OFRAK components fail to run; unpacking/packing specific file types fails.

**Cause**: External tools required by OFRAK components are not installed on the system.

**Solution**:
See [OFRAK CLI Configuring Dependencies](../ofrak-cli.md#configuring-dependencies--quickstart)

### build_image.py Dependency Errors

**Symptoms**: `ModuleNotFoundError: No module named 'pkg_resources'` or `ModuleNotFoundError: No module named 'yaml'` when running `build_image.py`.

**Cause**: The `setuptools` or `pyyaml` packages are not installed (see [Docker prerequisites](#docker)).

**Solution**:
```bash
make requirements-pip
make requirements-build-docker
```

### keystone-engine Import Error on macOS (M1/M2)

**Symptoms**: `ImportError: ERROR: fail to load the dynamic library` when importing or using OFRAK components that depend on `keystone-engine`.

**Cause**: On M1/M2 Macbooks, the `keystone-engine` dependency requires `cmake` to build properly. If `cmake` is not installed, the build step for the shared library can silently fail, leading to runtime import errors.

**Solution**:
1. Install cmake via Homebrew:
   ```bash
   brew install cmake
   ```
2. Reinstall keystone-engine:
   ```bash
   pip uninstall keystone-engine
   pip install keystone-engine
   ```

**Reference**: See [Issue #318](https://github.com/redballoonsecurity/ofrak/issues/318) for more details.

## Next Steps

- [Contributor Guide](../contributor-guide/getting-started.md) for development workflow
