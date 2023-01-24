# Changelog
All notable changes to `ofrak` will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/) and adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased](https://github.com/redballoonsecurity/ofrak/tree/master)

## [2.1.0](https://github.com/redballoonsecurity/ofrak/compare/ofrak-v2.0.0...ofrak-v2.1.0) - 2023-01-20
### Added
- `LiefAddSegmentConfig` now has an optional `physical_address` argument.
- New `identify` and `unpack` subcommands to CLI [#164](https://github.com/redballoonsecurity/ofrak/pull/164)
- Move GUI server to `ofrak_core`, startup GUI through CLI, add testing for server, make GUI pip installable. [#168](https://github.com/redballoonsecurity/ofrak/pull/168)
  - `python -m ofrak gui` starts the OFRAK GUI server.
- UBI and UBIFS filesystem analyzers / unpackers / packers added. [#173](https://github.com/redballoonsecurity/ofrak/pull/173), [#177](https://github.com/redballoonsecurity/ofrak/pull/177)
- Add APIs to open GUI in a script or after CLI commands complete. [#181](https://github.com/redballoonsecurity/ofrak/pull/181)
- Installing ofrak also installs it as a console tool, so for example `ofrak unpack ...` works, instead of requiring `python -m ofrak unpack...` [#181](https://github.com/redballoonsecurity/ofrak/pull/181)

### Changed
- Refactored `DataService` internals to more efficiently find resources affected by patches [#140](https://github.com/redballoonsecurity/ofrak/pull/140)

### Deprecated
- Deprecate `view_type.attributes_type` in favor of `AttributesType[view_type]` [#149](https://github.com/redballoonsecurity/ofrak/pull/149)

### Fixed
- Remove unneeded and slow `.save()` when unpacking filesystems [#171](https://github.com/redballoonsecurity/ofrak/pull/171)
- Fixed null pointer bug in Ghidra scripts.
- `SegmentInjectorModifier` deletes all descendants of the modified section, fixing a bug that would arrise when applying more than one segment modification.
- Added missing elf section types to ElfSectionType [#178](https://github.com/redballoonsecurity/ofrak/pull/178)
- Handled .rela placeholder segments in the same fashion as .got [#185](https://github.com/redballoonsecurity/ofrak/pull/185)

## [2.0.0](https://github.com/redballoonsecurity/ofrak/releases/tag/ofrak-v2.0.0) - 2023-01-03
### Added
- `ofrak` now contains all the components that were in the (now sunset) `ofrak_components` package.
- Add components for analyzing, unpacking, and repacking raw flash dumps.
- UF2 unpacker and packer added.
- Several new features to make tracking and installing external dependencies easier (for non-Docker users):
  - Components can now mark their external tool dependencies using the `external_dependencies` attribute.
  - CLI tool added to track and install dependencies & components:
    - `python -m ofrak list` lists installed OFRAK modules and/or components.
    - `python -m ofrak deps` shows and checks external (non-Python) dependencies of OFRAK components, and shows hints on how they might be installed.
  - `OFRAKContext` logs if a discovered component is missing an external dependency; these components can be excluded using the `exclude_components_missing_depenencies` parameter in `OFRAK`.
- Speed improvements to `Resource.unpack_recursively` method.

### Changed
- `Resource.{write_to, flush_to_disk}` now have optional `pack` parameter to pack before writing.
- Resource views are now updated when `Resource.save` is run.
- `DataService` was refactored for speed and clarity of implementation. It also now allows sibling Resources to overlap with each other.
- Free space components decoupled from ISA.
- `Filesystem.initialize_from_disk` raises `FileNotFoundError` when path does not exist or is not a file ([@galbwe](https://github.com/galbwe)).
- Rename `RawExtendModifier` to `BinaryExtendModifier`.
- `ElfProgramHeader` simplified to have only one method, `get_memory_permissions`.
- Switch to using PyPI versions of keystone & capstone.
- `PeOptionalHeader` divided into 32 and 64 bit.

### Removed
- Removed unused, untested APIs:
  - Removed `Resource.{get_data_index_within_parent, get_offset_within_root, get_data_unmapped_range, set_data_alignment, fetch, get_related_tags, get_all_attributes, move, get_siblings_as_view, get_siblings}`.
  - Removed `AssemblerServiceInterface.{assemble_many, assemble_file, assemble_files}`.
  - Removed `RawReplaceModifier`, `InjectorModifier`.
  - Removed `ElfProgramHeaderPermission`, replaced usage with `MemoryPermissions` (from `ofrak-type`).
  - Remove unused `Elf,{get_sections_after_index, get_sections_before_index, get_section_header_by_name, get_string_section_header`.
  - Removed `get_parent`/`get_elf` from Elf resource views, `UnanalyzedElfSegment`, `ElfSegmentStructureIndexAnalyzer`, `ElfSectionStructureIndexAnalyzer`, `ElfSymbolStructureIndexAnalyzer`, `ElfModifierUtils`.

### Fixed
- `Resource.create_child` takes either `data` or `data_range` arguments, but not both.
- Remove duplicated work from in resource service serialization, making it faster.
- Miscellaneous bugs in documentation.
- Added `beartype` as requirement for `ofrak`.
- Bump to `fun-coverage==0.2.0` for more accurate test coverage reporting.

### Security
- Bump `lief` dependency to 0.12.2 to avoid [vulnerability](lief-project/LIEF#763) in lower versions.
## 1.0.0 - 2022-09-02
### Added
Initial release. Hello world!
