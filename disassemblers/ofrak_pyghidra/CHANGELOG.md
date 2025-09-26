# Changelog
All notable changes to `ofrak-pyghidra` will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/) and adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased 0.2.0rc3](https://github.com/redballoonsecurity/ofrak/tree/master)

### Fixed
- Fix Ghidra and pyghidra CodeRegion unpacker to take into account the base address that ghidra sets for PIE executables.([#627](https://github.com/redballoonsecurity/ofrak/pull/627))
### Changed
- Reduce the decompilation time of PyGhidra by reusing cached unpacking results. ([#623](https://github.com/redballoonsecurity/ofrak/pull/623))
- Look for `ProgramAttributes` before unpacking. Do not pack when flushing to disk. Better error message when Ghidra raises "No load spec found". Added test for unpacking ihex with `ofrak_pyghidra` ([#637](https://github.com/redballoonsecurity/ofrak/pull/637))

## 0.1.0 - 2025-07-25

### Added
Initial release. Hello world!
