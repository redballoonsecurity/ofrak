# Changelog
All notable changes to `ofrak-patch-maker` will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/) and adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased](https://github.com/redballoonsecurity/ofrak/tree/master)

## [2.0.0](https://github.com/redballoonsecurity/ofrak/releases/tag/ofrak-patch-maker-v.2.0.0) - 2023-01-03
### Changed
- `Toolchain` interface uses `ArchInfo` instead of `ProgramAttributes` to remove dependency on `ofrak`.
- `bss_size_required` parameter added to `AssembledObject`.
- `segment_alignment` parameter added to `BOM`.
- Removed reference to obsolete `ofrak-componets` from README.md.

### Deprecated
- Deprecated `PatchMaker.allocate_bom` to remove dependency on `ofrak`. Use `ofrak==2.0.0`'s `Allocatable.allocate_bom` instead.

### Removed
- `Toolchain.get_required_alignment` method is now the property `Toolchain.segment_alignment`.
- Removed incomplete `LLVM_MACH_O_Parser` implementation (see [#156](https://github.com/redballoonsecurity/ofrak/issues/156)).

## 1.0.0 - 2022-09-02
### Added
Initial release. Hello world!
