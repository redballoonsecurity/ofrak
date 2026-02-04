# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Project Overview

OFRAK (Open Firmware Reverse Analysis Konsole) is a binary analysis and modification platform for reverse engineering firmware, executables, and file formats. See `README.md` for full details.

## Quick Reference Commands

```bash
# Development setup (core packages only - faster)
make develop-core

# Full setup including optional disassemblers
make develop

# Run tests for a package
make -C ofrak_core test

# Run single test
python3 -m pytest tests/path/to/test.py::TestClass::test_method -v

# Linting (from repo root)
make inspect                    # autoflake + black check
pre-commit run --all-files      # all hooks

# Type checking (from package directory)
python3 -m mypy

# Build frontend
cd frontend && npm install && npm run build


## Package Structure

Packages must be installed in dependency order:
1. `ofrak_type` - Primitive types (enums, Range)
2. `ofrak_io` - I/O utilities
3. `ofrak_patch_maker` - Binary patching toolchains (can be skipped on platforms where toolchains are difficult to install, or when patching functionality is not needed)
4. `ofrak_core` - Main framework (depends on above)
5. `pytest_ofrak` - Test utilities
6. `disassemblers/*` - Optional backends (angr, capstone, ghidra, binary_ninja, pyghidra)

Each package uses src layout (`src/` subdirectory) and has its own Makefile with `install`, `develop`, `inspect`, `test` targets.

## Architecture

- **Entry point**: `OFRAK` class → `discover()` backends → `run()` or `create_ofrak_context()`
- **Example scripts**: See `examples/` directory and [tutorial documentation](https://ofrak.com/docs/getting-started/basic-usage.html) for basic OFRAK usage patterns
- **Core abstraction**: `Resource` - represents binary data with tags, supports `unpack()`, `run()`, `get_data()`, `flush_data_to_disk()`
- **Component types**: `Analyzer`, `Modifier`, `Unpacker`, `Packer`, `Identifier` (in `ofrak/component/`)
- **Resource lifecycle**: create → identify → unpack → analyze/modify → pack → flush
- **Dependency injection framework**: `synthol` - components discovered via `ofrak.packages` entry points
- **Async**: All I/O is async; tests use `asyncio_mode="auto"`

Key directories in `ofrak_core/src/ofrak/`:
- `component/` - Base component classes
- `core/` - Format implementations (elf/, pe/, compression, filesystems, firmware)
- `model/` - Data models (Resource, ResourceTag, views)
- `service/` - Core services (data, resource, job, component locator)
- `frontend/` - Web GUI built with Svelte 4 and Vite. Build with `npm install && npm run build`

## Code Standards

- Line length: 100 chars (black enforced)
- Type hints required (mypy enforced)
- 100% test coverage required (fun-coverage enforced)
- Exceptions must be instantiated: `raise NotFoundError()` not `raise NotFoundError`

### Test Requirements

- **NEVER MOCK** - test with real code, real tools, real binary data
- Assume every test failure is an indication of a bug in code that must be fixed, until proven otherwise
- **Test Data Strategy**:
  - Write tests assuming real data exists in `tests/components/assets/`
  - Reference asset files by path (e.g., `tests/components/assets/sample.bin`)
  - Instruct user to place real test files: "Place test file at `tests/components/assets/sample.bin`"
  - **Remind user**: Test data must be suitable for public distribution (self-created, public domain, or permissively licensed)
  - Don't create synthetic data in test code
  - Don't generate test files programmatically

When creating tests, instruct the user:

```
Please place a real MyFormat test file at:
  tests/components/assets/sample.myformat

IMPORTANT: Test data must be suitable for public distribution, as the OFRAK
repository is open source and publicly accessible. Use test data that is:
- Created by you
- Public domain
- Permissively licensed
- Otherwise freely redistributable

You can obtain appropriate test data by:
- Creating your own test file with [tool]
- Using public domain samples from [source]
- Generating test cases yourself
- Extracting from openly licensed firmware/archives
```

See `docs/contributor-guide/getting-started.md` for full coding standards and docstring format.

## Contributing

- Update `CHANGELOG.md` and bump the **rc version** in `setup.py` for any package changes
- Changelogs follow Keep a Changelog format with PR links
- Pre-commit hooks must pass (install with `pre-commit install`)

See `CONTRIBUTING.md` for PR guidelines and maintainer info.
