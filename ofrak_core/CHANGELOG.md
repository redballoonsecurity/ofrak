# Changelog
All notable changes to `ofrak` will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/) and adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased](https://github.com/redballoonsecurity/ofrak/tree/master)
### Added
- Add a JFFS2 packer and unpacker. ([#326](https://github.com/redballoonsecurity/ofrak/pull/326))
- Add method to Resource and data service to search for patterns in its data ([#333](https://github.com/redballoonsecurity/ofrak/pull/333))
- Add search bars to GUI in order to search for a string or bytes within a resource. ([#345](https://github.com/redballoonsecurity/ofrak/pull/345))

### Changed
- Support uploading files in chunks to handle files larger than 2GB from the GUI ([#324](https://github.com/redballoonsecurity/ofrak/pull/324))

### Fixed

## [3.1.0](https://github.com/redballoonsecurity/ofrak/compare/ofrak-v3.0.0...ofrak-v3.1.0)
### Added
- Add `ElfLoadAlignmentModifier`, which reclaims unused alignment bytes between PT_LOAD segments in ELFs as free space. ([#302](https://github.com/redballoonsecurity/ofrak/pull/302))
- Add a "copy to clipboard" button to the "Show Snippet" view for easy exporting. ([#301](https://github.com/redballoonsecurity/ofrak/pull/301))
- Add a settings pane to the OFRAK GUI that supports theming and changing colors ([#309](https://github.com/redballoonsecurity/ofrak/pull/309))
- Add a button and interface in the OFRAK GUI to specifically select any component to run on a resource ([#287](https://github.com/redballoonsecurity/ofrak/pull/287))
- Add DDR pad support to the OFRAK GUI ([#322](https://github.com/redballoonsecurity/ofrak/pull/322))

### Fixed 
- Fixed a bug where clicking "Unpack" or "Identify" (for example) too quickly after loading a large resource causes an error that freezes up the whole GUI ([#297](https://github.com/redballoonsecurity/ofrak/pull/297))
- Bump `importlib-metadata` version to fix import errors ([#296](https://github.com/redballoonsecurity/ofrak/pull/296))
- Treat `libmagic`, `strings` as `ComponentExternalTools` so that they are considered dependencies. ([#299](https://github.com/redballoonsecurity/ofrak/pull/299/))
- Fixed GUI minimap bottom overlapping version number ([#327](https://github.com/redballoonsecurity/ofrak/pull/327))

## [3.0.0](https://github.com/redballoonsecurity/ofrak/compare/ofrak-v2.2.1...ofrak-v3.0.0)
### Added
- Add call to flush a resource to disk in the script whenever a user downloads a resource from the GUI. ([#277](https://github.com/redballoonsecurity/ofrak/pull/277))
- Generate dynamic, runnable script based on GUI actions and display the script in the GUI. ([#265](https://github.com/redballoonsecurity/ofrak/pull/265))
- Add `-f`/`--file` option to `ofrak gui` command to pre-load some files into OFRAK before opening the GUI, so they can be explored right away ([#266](https://github.com/redballoonsecurity/ofrak/pull/266))
- Add `-i`/`--import` option to the CLI to import and discover additional OFRAK Python packages when starting OFRAK. ([#269](https://github.com/redballoonsecurity/ofrak/pull/269))
- Add Identifier to tag `ComplexBlocks` as `LinkableSymbols` and Analyzer to copy attributes from a `ComplexBlock` to its `LinkableSymbol`. ([#226](https://github.com/redballoonsecurity/ofrak/pull/226))
- Add method to create new `LinkableSymbols` from symbols defined in a patch file. ([#226](https://github.com/redballoonsecurity/ofrak/pull/226))


### Changed
- Remove need to create Resources to pass source code and headers to `PatchFromSourceModifier` and `FunctionReplaceModifier` ([#249](https://github.com/redballoonsecurity/ofrak/pull/249))
- Choose Analyzer components which output the entirety of a view, rather than piece by piece, which would choose the wrong Analyzer sometimes. ([#264](https://github.com/redballoonsecurity/ofrak/pull/264))
- Generate LinkableBinary stubs as strong symbols, so linker use them to override weak symbols in patch ([#259](https://github.com/redballoonsecurity/ofrak/pull/259))
- Limit stub file creation for linkable BOMs to only those required by a patch. ([#226](https://github.com/redballoonsecurity/ofrak/pull/226))

### Fixed
- Fix bug where `ComponentExternalTool` would raise an error when checking whether a tool was installed returned a non-zero exit value ([#289](https://github.com/redballoonsecurity/ofrak/pull/289))
- Fix bug where jumping to a multiple of `0x10` in the GUI went to the previous line ([#254](https://github.com/redballoonsecurity/ofrak/pull/254))
- Fix installing on Windows, as well as small GUI style fixes for Windows ([#261](https://github.com/redballoonsecurity/ofrak/pull/261))
- Fixed `Uf2File` identifier so that it correctly tags UF2 files with `Uf2File` ([#283](https://github.com/redballoonsecurity/ofrak/pull/283))

## [2.2.1](https://github.com/redballoonsecurity/ofrak/compare/ofrak-v2.2.0...ofrak-v2.2.1) - 2023-03-08
### Added
- Add GUI features
  - Keyboard shortcuts ([#210](https://github.com/redballoonsecurity/ofrak/pull/210))
  - Button to add a tag to a resource ([#215](https://github.com/redballoonsecurity/ofrak/pull/215))
  - Browser tab title contains current resource caption ([#230](https://github.com/redballoonsecurity/ofrak/pull/230))
- Add a way to sort and filter by data length or offset ([#220](https://github.com/redballoonsecurity/ofrak/pull/220))
- Add caption to ElfProgramHeader ([#223](https://github.com/redballoonsecurity/ofrak/pull/223))
- Add baseline support for running pip-installing ofrak on Windows ([#228](https://github.com/redballoonsecurity/ofrak/pull/228), [#239](https://github.com/redballoonsecurity/ofrak/pull/239), [#242](https://github.com/redballoonsecurity/ofrak/pull/242), [#246]( #246))

### Changed
- Updates to Flash components: ([#195](https://github.com/redballoonsecurity/ofrak/pull/195))
  - Flash components now support more than one occurrence of the same field type in `FlashAttributes`.
  - `FlashOobResourceUnpacker` continues to unpack even if blocks do not perfectly align at end of the `FlashOobResource` (this is useful for real-world flash dumps).
- Tweak how errors are raised when auto-running components, so the actual root cause is not buried ([#219](https://github.com/redballoonsecurity/ofrak/pull/219))
- Show mapped resource captions on hover in the hex view ([#221](https://github.com/redballoonsecurity/ofrak/pull/221))
- Change how resources are stored to making deleting (and thus packing) much faster ([#201](https://github.com/redballoonsecurity/ofrak/pull/201))
- Use non-blocking `asyncio.create_subprocess_exec` calls in components ([#53](https://github.com/redballoonsecurity/ofrak/issues/53))

### Fixed
- Fix bug where initially loaded GUI resource has collapsed children ([#209](https://github.com/redballoonsecurity/ofrak/pull/209))
- Fix bug in GUI where "jump to offset" feature in hex view rounded up instead of down ([#243](https://github.com/redballoonsecurity/ofrak/pull/243))
- Support more OpenWRT TRX files by making fewer assumptions about the partitions ([#216](https://github.com/redballoonsecurity/ofrak/pull/216))
- Fix some OS-specific problems (libmagic install, log file path) preventing OFRAK install on Windows ([#239](https://github.com/redballoonsecurity/ofrak/pull/239))

## [2.2.0](https://github.com/redballoonsecurity/ofrak/compare/ofrak-v2.1.1...ofrak-v2.2.0) - 2023-02-01
### Fixed
- Fix bug in data service that can cause mangled internal state [#197](https://github.com/redballoonsecurity/ofrak/pull/197)
- Fix long-broken `OFRAK.set_id_service` [#198](https://github.com/redballoonsecurity/ofrak/pull/198)
- Fix bug in `SegmentInjectorModifier` that resulted in deleting more resources than necessary [#200](https://github.com/redballoonsecurity/ofrak/pull/200)

### Added
- Replace unofficial p7zip with official 7zip package
- File browser dialog in the GUI
- Area in the GUI to jump to a given data offset
- GUI command line now has a flag to not automatically open the browser

### Changed
- GUI is much faster, especially for resources with hundreds of thousands of children [#191](https://github.com/redballoonsecurity/ofrak/pull/191)
- Resources whose data gets modified are now listed in the `resource_modified` field of component results [#200](https://github.com/redballoonsecurity/ofrak/pull/200)

## [2.1.1](https://github.com/redballoonsecurity/ofrak/compare/ofrak-v2.1.0...ofrak-v2.1.1) - 2023-01-25
### Fixed
- GUI uses correct attribute class names again (not *AutoAttributes)

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
