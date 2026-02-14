# Changelog
All notable changes to `ofrak-ghidra` will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/) and adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased 0.2.0rc4](https://github.com/redballoonsecurity/ofrak/tree/master)

### Added
- Add `use_sudo` config option for non-root Ghidra server management ([#707](https://github.com/redballoonsecurity/ofrak/pull/707))
- Add OFRAK requirements, requirement to test mapping, test specifications ([#656](https://github.com/redballoonsecurity/ofrak/pull/656))
- Add mypy type checking enforcement to `make test` ([#702](https://github.com/redballoonsecurity/ofrak/pull/702))

### Changed
- Minor update to OFRAK Community License, add OFRAK Pro License ([#478](https://github.com/redballoonsecurity/ofrak/pull/478))
- Move to OpenJDK version 17 with the docker container move to Debian 12 ([#502](https://github.com/redballoonsecurity/ofrak/pull/502))

### Fixed
- Raise an error when Ghidra server start/stop commands fail ([#707](https://github.com/redballoonsecurity/ofrak/pull/707))
- Bump `aiohttp` to >=3.13.3 to address CVE-2025-69223 ([#693](https://github.com/redballoonsecurity/ofrak/pull/693))
- Speedup: do not run Ghidra auto-analysis upon importing a program. ([#473](https://github.com/redballoonsecurity/ofrak/pull/473))
- Ensure large 64-bit addresses are interpreted as unsigned. ([#474](https://github.com/redballoonsecurity/ofrak/pull/474))
- Update `GhidraDecompilationAnalyzer` to match API in ofrak 0.3.0rc10 ([#600](https://github.com/redballoonsecurity/ofrak/pull/600))
- Handle escape (\) character in the JSON going from Java (Ghidra) to Python ([#604](https://github.com/redballoonsecurity/ofrak/pull/604))
- Fix Ghidra and pyghidra CodeRegion unpacker to take into account the base address that ghidra sets for PIE executables.([#627](https://github.com/redballoonsecurity/ofrak/pull/627))
- Pin java version ([#683](https://github.com/redballoonsecurity/ofrak/pull/683))
- Fix `_do_ghidra_analyze_and_serve` crash when Ghidra exits unexpectedly by capturing stderr ([#702](https://github.com/redballoonsecurity/ofrak/pull/702))
- Fix `GhidraDecompilationAnalyzer` silently swallowing non-JSONDecodeError exceptions and incorrect error string handling ([#702](https://github.com/redballoonsecurity/ofrak/pull/702))
- Fix `_arch_info_to_processor_id` to raise an explicit error for unsupported ISAs instead of proceeding with `None` family ([#702](https://github.com/redballoonsecurity/ofrak/pull/702))

## 0.1.1 - 2024-02-15
### Added
- Added typing support to the ofrak-ghidra package. This is helpful for users who use `mypy` and `ofrak_ghidra` in a project.
- Added GhidraDecompilationAnalyzer to retrieve the decompilation of a complex block. ([#453](https://github.com/redballoonsecurity/ofrak/pull/453))

## 0.1.0 - 2022-08-09
### Added
Initial release. Hello world!
