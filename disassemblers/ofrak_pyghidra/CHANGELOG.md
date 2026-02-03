# Changelog
All notable changes to `ofrak-pyghidra` will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/) and adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased 0.2.0rc6](https://github.com/redballoonsecurity/ofrak/tree/master)

### Added
- Support `ProgramMetadata` attribute for passing entry points and base address to PyGhidra
- Support `MemoryRegionPermissions` attribute for fine-grained memory region permission control
- Add a PyGhidra custom load analyzer to allow for loading programs with a custom layout ([#677](https://github.com/redballoonsecurity/ofrak/pull/677))
- Add detailed logging output and progress indicators to standalone analysis script ([#672](https://github.com/redballoonsecurity/ofrak/pull/672))

### Fixed
- Fix Ghidra and pyghidra CodeRegion unpacker to take into account the base address that ghidra sets for PIE executables.([#627](https://github.com/redballoonsecurity/ofrak/pull/627))
- Fix auto discovery of `PyGhidraDecompilationAnalyzer` ([#650](https://github.com/redballoonsecurity/ofrak/pull/650))
- Fix redundant re-analysis of complex blocks in the standalone analysis script ([#672](https://github.com/redballoonsecurity/ofrak/pull/672))

### Changed
- Reduce the decompilation time of PyGhidra by reusing cached unpacking results. ([#623](https://github.com/redballoonsecurity/ofrak/pull/623))
- Improve `ofrak_pyghidra` decompilation: more strings and symbol names for cross-references in decompilation. ([#633](https://github.com/redballoonsecurity/ofrak/pull/633))
- Improve unpacking logic, error messages, and testing for `ofrak_pyghidra` auto analyzer ([#637](https://github.com/redballoonsecurity/ofrak/pull/637))

## 0.1.0 - 2025-07-25

### Added
Initial release. Hello world!
