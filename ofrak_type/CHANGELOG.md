# Changelog
All notable changes to `ofrak-type` will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/) and adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased](https://github.com/redballoonsecurity/ofrak/tree/master)

### Added
- Added tests to the `ofrak_type_test` package ([#591](https://github.com/redballoonsecurity/ofrak/pull/591))

### Changed
- Minor update to OFRAK Community License, add OFRAK Pro License ([#478](https://github.com/redballoonsecurity/ofrak/pull/478))


### Fixed
- Fix ValueError after analyzing ELF with invalid MemoryPermissions ([#581](https://github.com/redballoonsecurity/ofrak/pull/581))

## [2.2.0](https://github.com/redballoonsecurity/ofrak/compare/ofrak-type-v2.1.0...ofrak-type-v2.2.0)

### Added
- `ProcessorType.CORTEX_A72`
- LinkableSymbolType enum for generalized representation of symbol types (essentially functions vs. data)
- Added a `GENERIC_ARM_BE8` ProcessorType for ARM BE8

## [2.1.0](https://github.com/redballoonsecurity/ofrak/compare/ofrak-type-v2.0.0...ofrak-type-v2.1.0) - 2023-01-20
### Added
- `ProcessorType.CORTEX_A55`

## [2.0.0](https://github.com/redballoonsecurity/ofrak/releases/tag/ofrak-type-v2.0.0) - 2023-01-03
### Added
- Add `ArchInfo` to describe an architecture.
- Classes in package all discoverable at `ofrak_type`, e.g., `from ofrak_type import Range`.

### Changed
- Removed reference to obsolete `ofrak_components` from README.md.
- Integer values for `MemoryPermission.R` and `MemoryPermission.X` now correctly match bitfield values.

## 1.0.0 - 2022-09-02
### Added
Initial release. Hello world!
