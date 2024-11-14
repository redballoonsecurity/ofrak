# Changelog
All notable changes to `ofrak-ghidra` will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/) and adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased](https://github.com/redballoonsecurity/ofrak/tree/master)

### Changed
- Minor update to OFRAK Community License, add OFRAK Pro License ([#478](https://github.com/redballoonsecurity/ofrak/pull/478))

### Fixed
- Speedup: do not run Ghidra auto-analysis upon importing a program. ([#473](https://github.com/redballoonsecurity/ofrak/pull/473))
- Ensure large 64-bit addresses are interpreted as unsigned. ([#474](https://github.com/redballoonsecurity/ofrak/pull/474))

## 0.1.1 - 2024-02-15
### Added
- Added typing support to the ofrak-ghidra package. This is helpful for users who use `mypy` and `ofrak_ghidra` in a project.
- Added GhidraDecompilationAnalyzer to retrieve the decompilation of a complex block. ([#453](https://github.com/redballoonsecurity/ofrak/pull/453))

## 0.1.0 - 2022-08-09
### Added
Initial release. Hello world!
