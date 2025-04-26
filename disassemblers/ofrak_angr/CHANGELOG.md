# Changelog
All notable changes to `ofrak-angr` will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/) and adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased](https://github.com/redballoonsecurity/ofrak/tree/master)

### Changed
- Update to latest angr==9.2.93, which also necessitates Python >= 3.8.
- Refactored AngrDecompilationAnalysis/Analyzer to use generic components in ofrak core. ([#453](https://github.com/redballoonsecurity/ofrak/pull/453))
- Minor update to OFRAK Community License, add OFRAK Pro License ([#478](https://github.com/redballoonsecurity/ofrak/pull/478))

### Fixed
- Add `importlib-resources` dependency as workaround for z3-solver dependency issue. ([#401](https://github.com/redballoonsecurity/ofrak/pull/401))

## 1.0.1 - 2023-06-26
### Fixed
- Fix bug in THUMB mode handling of BasicBlocks and Instruction. ([#304](https://github.com/redballoonsecurity/ofrak/pull/304))

## 1.0.0 - 2022-01-25
### Added
Initial release. Hello world!
