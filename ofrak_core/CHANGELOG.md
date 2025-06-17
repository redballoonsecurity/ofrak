# Changelog
All notable changes to `ofrak` will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/) and adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased: 3.3.0rc7](https://github.com/redballoonsecurity/ofrak/tree/master)
### Added
- Add license check command to prompt users about community or pro licenses. ([#478](https://github.com/redballoonsecurity/ofrak/pull/478))
- Support `application/vnd.android.package-archive` mime type for APKs, which is returned by newer versions of libmagic ([#470](https://github.com/redballoonsecurity/ofrak/pull/470))
- Add links to other resources and locations in comments with an autocomplete feature in the comment view. ([#447](https://github.com/redballoonsecurity/ofrak/pull/447)) 
- Add modifier to add and remove sections using lief. ([#443](https://github.com/redballoonsecurity/ofrak/pull/443))
- Add tabbed content views and a decompilation view to the OFRAK GUI. ([#436](https://github.com/redballoonsecurity/ofrak/pull/436/))
- Refactor HexView and related components to use mousewheel instead of scroll and compartmentalize all comonents to src/hex. ([#427](https://github.com/redballoonsecurity/ofrak/pull/427))
- Add an improved ISO9660 packer that leverages `mkisofs` instead of PyCdLib. ([#393](https://github.com/redballoonsecurity/ofrak/pull/393))
- Add UEFI binary unpacker. ([#399](https://github.com/redballoonsecurity/ofrak/pull/399))
- Add recursive identify functionality in the GUI. ([#435](https://github.com/redballoonsecurity/ofrak/pull/435))
- Add generic DecompilationAnalysis classes. ([#453](https://github.com/redballoonsecurity/ofrak/pull/453))
- `PatchFromSourceModifier` bundles src and header files into same temporary directory with BOM and FEM ([#517](https://github.com/redballoonsecurity/ofrak/pull/517))
- Add support for running on Windows to the `Filesystem` component. ([#521](https://github.com/redballoonsecurity/ofrak/pull/521))
- Add `JavaArchive` resource tag ([#492](https://github.com/redballoonsecurity/ofrak/pull/492))
- Add new method for allocating `.bss` sections using free space ranges that aren't mapped to data ranges. ([#505](https://github.com/redballoonsecurity/ofrak/pull/505))
- Add PyGhidra support along with a disassembly backend to pull disassembler analysis from a json. ([#556](https://github.com/redballoonsecurity/ofrak/pull/556))
- Add `JavaArchive` resource tag ([#492](https://github.com/redballoonsecurity/ofrak/pull/492))
- Pulled `Allocatable._align_range` out to standalone function `allocate_range_start` ([#575](https://github.com/redballoonsecurity/ofrak/pull/575))

### Fixed
- Improved flushing of filesystem entries (including symbolic links and other types) to disk. ([#373](https://github.com/redballoonsecurity/ofrak/pull/373))
- Fix `java` and `apktool` CLI arguments for checking components. ([#390](https://github.com/redballoonsecurity/ofrak/pull/390))
- Bump GitPython version from 3.1.35 to 3.1.41 to mitigate CVEs. ([#400](https://github.com/redballoonsecurity/ofrak/pull/400))
- Fixes erroneous Free Space Modifier expectation that resource parents are memory views. ([#404](https://github.com/redballoonsecurity/ofrak/pull/404))
- Prevent `_find_and_delete_overlapping_children` from deleting children which are next to the freed region, but not overlapping. ([#396](https://github.com/redballoonsecurity/ofrak/pull/396))
- Fixed front end "Replace" button. Before it was appending new data instead of replacing it as intended. ([#403](https://github.com/redballoonsecurity/ofrak/pull/403))
- Fix dragging and dropping in the GUI. ([#407](https://github.com/redballoonsecurity/ofrak/pull/407))
- Fix running scripts without a project selected, and without a config selected. ([#407](https://github.com/redballoonsecurity/ofrak/pull/407))
- Fix bug in OFRAK GUI server which causes an error when parsing a default config value of bytes. ([#409](https://github.com/redballoonsecurity/ofrak/pull/409))
- Set default fallback font to system default monospace, instead of variable-width sans-serif. ([#422](https://github.com/redballoonsecurity/ofrak/pull/422))
- View resource attribute string values containing only digits primarily as strings, alternatively as hex numbers. ([#423](https://github.com/redballoonsecurity/ofrak/pull/423))
- Fix bug where PJSON deserializer fails to deserialze `ComponentConfig` dataclasses have a field with a default value of `None`. ([#506](https://github.com/redballoonsecurity/ofrak/pull/506))
- Fix bug where calling `Resource.remove_tag` on both a tag class and a class that inherits from that class causes a `KeyError` on resource save. ([#510](https://github.com/redballoonsecurity/ofrak/pull/510))
- Use PyPI version of `bincopy`, upgrade to version 20.0.0 ([#528](https://github.com/redballoonsecurity/ofrak/pull/528))
- Fix bugs on Windows arising from using `os.path` methods when only forward-slashes are acceptable ([#521](https://github.com/redballoonsecurity/ofrak/pull/521))
- Made some changes to OFRAK test suite to improve test coverage on Windows ([#487](https://github.com/redballoonsecurity/ofrak/pull/487))
- Fix usage of `NamedTemporaryFile` with external tools on Windows ([#486](https://github.com/redballoonsecurity/ofrak/pull/486))
- Fixed endianness issue in DTB raw byte identifier ([#492](https://github.com/redballoonsecurity/ofrak/pull/492))
- Fix unintentional ignoring of cpio errors introduced in [#486](https://github.com/redballoonsecurity/ofrak/pull/486) ([#555](https://github.com/redballoonsecurity/ofrak/pull/555]))
- `Data` resource attribute always corresponds to value of `Resource.get_data_range_within_root` ([#559](https://github.com/redballoonsecurity/ofrak/pull/559))
- Fixed endianness issue in DTB raw byte identifier ([#492](https://github.com/redballoonsecurity/ofrak/pull/492))
- Fixed bugs with PJSON serialization for some component configs in the front end ([#437](https://github.com/redballoonsecurity/ofrak/pull/437))
- Make `ofrak[test]` dependencies on `ofrak-capstone` and `ofrak-angr` optional to avoid circular-dependency issues ([#571](https://github.com/redballoonsecurity/ofrak/pull/571))
- Fix broken link in docs ([#574](https://github.com/redballoonsecurity/ofrak/pull/574))
- Fix ValueError after analyzing ELF with invalid MemoryPermissions ([#581](https://github.com/redballoonsecurity/ofrak/pull/581))
- Fix build pipeline failures by pinning `orjson`, a recent minor version of which breaks the PJSON tests. ([#584](https://github.com/redballoonsecurity/ofrak/pull/584))
- Improve performance of ResourceAttributes.get_indexable_attributes() ([#586](https://github.com/redballoonsecurity/ofrak/pull/586))
- Remove `Data` attribute to eliminate duplicative indexing in `ResourceService`, resulting in performance improvement for all workflows ([#589](https://github.com/redballoonsecurity/ofrak/pull/589))

### Changed
- Miscellaneous updates to the documentation. ([#592](https://github.com/redballoonsecurity/ofrak/pull/592))
- By default, the ofrak log is now `ofrak-YYYYMMDDhhmmss.log` rather than just `ofrak.log` and the name can be specified on the command line ([#480](https://github.com/redballoonsecurity/ofrak/pull/480))
- In `GzipUnpacker`, use the standard python `zlib` library to compress small files and decompress all files. Use `pigz` if it is installed to compress files 1MB and larger. ([#472](https://github.com/redballoonsecurity/ofrak/pull/472) and [#485](https://github.com/redballoonsecurity/ofrak/pull/485))
- Change `FreeSpaceModifier` & `PartialFreeSpaceModifier` behavior: an optional stub that isn't free space can be provided and fill-bytes for free space can be specified. ([#409](https://github.com/redballoonsecurity/ofrak/pull/409))
- `Resource.flush_to_disk` method renamed to `Resource.flush_data_to_disk`. ([#373](https://github.com/redballoonsecurity/ofrak/pull/373))
- `build_image.py` supports building Docker images with OFRAK packages from any ancestor directory. ([#425](https://github.com/redballoonsecurity/ofrak/pull/425))
- Partially reverted [#150](https://github.com/redballoonsecurity/ofrak/pull/150) so entropy C code is called with `ctypes` again, but maintaining the current API and automatic compilation by `setup.py`. ([#482](https://github.com/redballoonsecurity/ofrak/pull/482))
- Minor update to OFRAK Community License, add OFRAK Pro License ([#478](https://github.com/redballoonsecurity/ofrak/pull/478))
- Update python to 3.9 as main version used and tested (including in default docker image build) ([#502](https://github.com/redballoonsecurity/ofrak/pull/502))
- Update OpenJDK to version 17, remove unused qemu package ([#502](https://github.com/redballoonsecurity/ofrak/pull/502))
- Update resource tag File to inherit from GenericBinary ([#492](https://github.com/redballoonsecurity/ofrak/pull/492))
- Update auto-run component logic to run all Analyzers, not just the most specific ([#492](https://github.com/redballoonsecurity/ofrak/pull/492))
- Revamp magic identification for significant speed improvements ([#492](https://github.com/redballoonsecurity/ofrak/pull/492))
  - Refactor magic identification to use one identifier, named `MagicIdentifier`
  - Rename `MagicMimeIdentifier` to `MagicMimePattern`, as it is run by `MagicIdentifier`
  - Rename `MagicDescriptionIdentifier` to `MagicDescriptionPattern`, as it is run by `MagicIdentifier`
  - Add `RawMagicPattern` to efficiently run custom magic byte search logic within `MagicIdenfifier`
  - Update registered identifiers to make use of new `MagicIdentifier` for following resource tags: `Apk`, `Bzip2Data`, `CpioFilesystem`, `DeviceTreeBlob`, `Elf`, `Ext2Filesystem`, `Ext3Filesystem`, `Ext4Filesystem`, `GzipData`, `ISO9660Image`, `Jffs2Filesystem`, `LzmaData`, `XzData`, `LzoData`, `OpenWrtTrx`, `Pe`, `RarArchive`, `SevenZFilesystem`, `SquashfsFilesystem`, `TarArchive`, `Ubi`, `Ubifs`, `Uf2File`, `UImage`, `ZipArchive`, `ZlibData`, `ZstdData`
- Update `Instruction.get_assembly` to by synchronous ([#539](https://github.com/redballoonsecurity/ofrak/issues/539))
- Update orjson to ~=3.10.12 ([#562](https://github.com/redballoonsecurity/ofrak/pull/562/files))

### Deprecated
- `Resource.flush_to_disk` deprecated in favor of `Resource.flush_data_to_disk`. ([#373](https://github.com/redballoonsecurity/ofrak/pull/373), [#567](https://github.com/redballoonsecurity/ofrak/pull/568))

### Removed
- Removed `Instruction.disassembly` from `Instruction` class: use `Instruction.get_assembly()` instead ([#539](https://github.com/redballoonsecurity/ofrak/issues/539))

### Security
- Update aiohttp to 3.10.11 ([#522](https://github.com/redballoonsecurity/ofrak/pull/522))
- Update pycryptogrpahy to version 43.0.3. ([#525](https://github.com/redballoonsecurity/ofrak/pull/525))
- Bump `lief` dependency to 0.16.1 to address [vulnerability](https://github.com/redballoonsecurity/ofrak/security/dependabot/31) in lower versions ([#502](https://github.com/redballoonsecurity/ofrak/pull/502), [#562](https://github.com/redballoonsecurity/ofrak/pull/562/files))
- Update `vite` and `esbuild` to newer versions to address dependabot warnings ([#595](https://github.com/redballoonsecurity/ofrak/pull/595))

## [3.2.0](https://github.com/redballoonsecurity/ofrak/compare/ofrak-v3.1.0...ofrak-v3.2.0)
### Added
- Add a JFFS2 packer and unpacker. ([#326](https://github.com/redballoonsecurity/ofrak/pull/326))
- Add method to Resource and data service to search for patterns in its data ([#333](https://github.com/redballoonsecurity/ofrak/pull/333))
- Add search bars to GUI in order to search for a string or bytes within a resource. ([#345](https://github.com/redballoonsecurity/ofrak/pull/345))
- Add Identifier, Unpacker, Packer for Intel Hex format. ([#349](https://github.com/redballoonsecurity/ofrak/pull/349))
- Add unpackers for EXT filesystems (versions 2 through 4). ([#337](https://github.com/redballoonsecurity/ofrak/pull/337))
- A new feature that allows users to create an OFRAK "project" that contains a collection of scripts and binaries. ([#360](https://github.com/redballoonsecurity/ofrak/pull/360))

### Changed
- Support uploading files in chunks to handle files larger than 2GB from the GUI ([#324](https://github.com/redballoonsecurity/ofrak/pull/324))

### Fixed
- Save resources affected by data patches and dependency updates on a resource being saved ([#355](https://github.com/redballoonsecurity/ofrak/pull/355))

### Security
- Updated GitPython to version 3.1.35 as per CVE-2023-40590 and CVE-2023-41040

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
