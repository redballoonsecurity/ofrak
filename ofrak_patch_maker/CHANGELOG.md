# Changelog
All notable changes to `ofrak-patch-maker` will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/) and adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased](https://github.com/redballoonsecurity/ofrak/tree/master)

## [4.0.1](https://github.com/redballoonsecurity/ofrak/compare/ofrak-patch-maker-v.4.0.0...ofrak-patch-maker-v.4.0.1)
### Added
- Interface to iterate over all Toolchain implementations ([#287](https://github.com/redballoonsecurity/ofrak/pull/287))

### Fixed
- Localize magic import ([#299](https://github.com/redballoonsecurity/ofrak/pull/299))

## [4.0.0](https://github.com/redballoonsecurity/ofrak/compare/ofrak-patch-maker-v.3.0.0...ofrak-patch-maker-v.4.0.0)

### Changed
- Discard `.altinstructions` section when linking
- Use `SUBALIGN(0)` for `.bss` sections
- Force literal pool at end of function for AARCH64 using `-mpc-relative-literal-loads`

### Added
- `-fno-optimize-sibling-calls` flag added to AVR toolchain.
- `-fno-pic` flag added to the GNU_10_Toolchain to omit GOTs in patches (FEMs) against binaries that aren't dynamically linked. (see [#245](https://github.com/redballoonsecurity/ofrak/pull/245))
- Add methods to parse relocation symbols from object files.
- Extend parsed symbol dictionary to include LinkableSymbolType.
- Extend AssembledObject and BOM types to include relocation and unresolved symbols.
- Add separate data sections support to LLVM toolchain, and add general flag for including subsections

### Changed
- Switch to standard GCC-like frontend for LLVM, which supports C attribute(weak)
- Treat weak symbols as "undefined" in BOM, so alternative, strong definitions can be searched
- Pass `-mmcu` value to the AVR preprocessor.
- Raise a more descriptive error on toolchain failure.

### Fixed
- Toolchain `preprocess()` method now returns the path to the preprocessed file.

## [3.0.0](https://github.com/redballoonsecurity/ofrak/compare/ofrak-patch-maker-v.2.0.0...ofrak-patch-maker-v.3.0.0) - 2023-01-20
### Added
- Optional permission map parameter to `Allocatable.allocate_bom`, which enables developers to express where 
segments of one set of permissions may be placed in the destination binary. For example, a developer may specify
to place `MemoryPermissions.R` `Segments` in destination program `MemoryRegions` of `MemoryPermissions.R` 
or `MemoryPermissions.RX`.

### Changed
- `PatchMaker` is now initialized with an existing `Toolchain` instance. GNU toolchain implementations are split into separate files.
- Make toolchain names in `toolchain.conf` more specific:
  - `GNU_ARM_NONE` changed to `GNU_ARM_NONE_EABI_10_2_1`.
  - `GNU_X86_64_LINUX` changed to `GNU_X86_64_LINUX_EABI_10_3_0`.

### Removed
- Removed `ToolchainVersion`.

## [2.0.0](https://github.com/redballoonsecurity/ofrak/releases/tag/ofrak-patch-maker-v.2.0.0) - 2023-01-03
### Changed
- `Toolchain` interface uses `ArchInfo` instead of `ProgramAttributes` to remove dependency on `ofrak`.
- `bss_size_required` parameter added to `AssembledObject`.
- `segment_alignment` parameter added to `BOM`.
- Removed reference to obsolete `ofrak_components` from README.md.

### Deprecated
- Deprecated `PatchMaker.allocate_bom` to remove dependency on `ofrak`. Use `ofrak==2.0.0`'s `Allocatable.allocate_bom` instead.

### Removed
- `Toolchain.get_required_alignment` method is now the property `Toolchain.segment_alignment`.
- Removed incomplete `LLVM_MACH_O_Parser` implementation (see [#156](https://github.com/redballoonsecurity/ofrak/issues/156)).

## 1.0.0 - 2022-09-02
### Added
Initial release. Hello world!
