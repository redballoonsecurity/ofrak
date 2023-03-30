# Changelog
All notable changes to `ofrak-type` will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/) and adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased](https://github.com/redballoonsecurity/ofrak/tree/master)

### Added
- LinkableSymbolType enum for generalized representation of symbol types (essentially functions vs. data)

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
