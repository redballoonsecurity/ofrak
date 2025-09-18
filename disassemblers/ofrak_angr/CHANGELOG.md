# Changelog
All notable changes to `ofrak-angr` will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/) and adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased 1.1.0rc3](https://github.com/redballoonsecurity/ofrak/tree/master)

### Changed
- Update to latest angr==9.2.93, which also necessitates Python >= 3.8.
- Add decompilation using angr backend ([#453](https://github.com/redballoonsecurity/ofrak/pull/453), [#600](https://github.com/redballoonsecurity/ofrak/pull/600))
- Minor update to OFRAK Community License, add OFRAK Pro License ([#478](https://github.com/redballoonsecurity/ofrak/pull/478))

### Fixed
- Add `importlib-resources` dependency as workaround for z3-solver dependency issue. ([#401](https://github.com/redballoonsecurity/ofrak/pull/401))
- Fixed bug in Angr backend unpacking BasicBlock that don't have an exit address ([#615](https://github.com/redballoonsecurity/ofrak/pull/615))

## 1.0.1 - 2023-06-26
### Fixed
- Fix bug in THUMB mode handling of BasicBlocks and Instruction. ([#304](https://github.com/redballoonsecurity/ofrak/pull/304))

## 1.0.0 - 2022-01-25
### Added
Initial release. Hello world!
