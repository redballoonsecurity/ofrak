# OFRAK Requirements

This page outlines the requirements for OFRAK.

OFRAK's design, first and foremost, should be user friendly.

Broadly speaking, there are three types of people who use OFRAK:

- **OFRAK Users**: Software engineers and security researchers who use existing features and components as a library to implement simple to advanced OFRAK workflows.
- **OFRAK Contributors**: Experienced engineers who, in addition to writing workflows, also contribute modules and components based on the OFRAK framework.
- **OFRAK Developers**: Engineers who maintain the core OFRAK code.

## OFRAK Requirements
OFRAK requirements are expressed in a series of epics: unpack binary files, analyze binary files, modify binary files, pack binary files, and have helpful, comprehensive documentation. Each epic is further expressed as a series of user stories.

Requirements are divided into the following categories, and all have unique identifiers:

1. Unpack binary files
2. Analyze binary files
3. Modify binary files
4. Pack binary files
5. OFRAK Documentation
6. Assemble and compile source code into injectable payloads

### 1. Unpack binary files

| Req ID | User Story (Requirement) | User Type | Validation |
|--------|--------------------------|-----------|------------|
| REQ1.1 | As an OFRAK contributor, I want to implement an unpacker using a well-defined interface so that it is easy to add new unpackers. | OFRAK Contributor | Unpacker interface is defined in [Unpacker][ofrak.component.unpacker]; see the multiple unpacker tests in [tests/components](https://github.com/redballoonsecurity/ofrak/blob/master/ofrak_core/tests/components) |
| REQ1.2 | As an OFRAK user, I want to receive an abstract binary analysis object, so the interface does not change depending on the analyzer used for complex blocks, basic blocks, symbols, instructions, and the control flow graph. | OFRAK User | OFRAK contains test patterns for these abstract analysis objects in [pytest_ofrak/patterns](https://github.com/redballoonsecurity/ofrak/tree/master/pytest_ofrak/src/pytest_ofrak/patterns): implementations of these test for different analysis backends include: [test_unpackers (Angr)](https://github.com/redballoonsecurity/ofrak/blob/master/disassemblers/ofrak_angr/tests/test_unpackers.py), [test_unpackers (Ghidra)](https://github.com/redballoonsecurity/ofrak/blob/master/disassemblers/ofrak_ghidra/tests/test_unpackers.py), and [test_ofrak_capstone](https://github.com/redballoonsecurity/ofrak/blob/master/disassemblers/ofrak_capstone/tests/test_ofrak_capstone.py) |
| REQ1.3 | As an OFRAK user, I want to use a library of built-in unpackers to unpack commonly occurring binary formats. | OFRAK User | See the multiple unpacker tests in [tests/components](https://github.com/redballoonsecurity/ofrak/blob/master/ofrak_core/tests/components) |
| REQ1.4 | As an OFRAK user, I want to unpack a compressed filesystem of known format into a tree-like structure, and export its contents to disk so that it can be examined outside of OFRAK. | OFRAK User | [test_filesystem_component](https://github.com/redballoonsecurity/ofrak/blob/master/ofrak_core/tests/components/test_filesystem_component.py) |
| REQ1.5 | As an OFRAK user, I want to programmatically invoke a specific unpacker on a specific binary so that I can control which unpackers run. | OFRAK User | [test_unpacker_with_default](https://github.com/redballoonsecurity/ofrak/blob/master/ofrak_core/tests/unit/component/test_default_config.py) |
| REQ1.6 | As an OFRAK user, I want to automatically unpack a binary, so I don’t have to manually pick analyzers and unpackers. | OFRAK User | [test_unpack_pack_unpack](https://github.com/redballoonsecurity/ofrak/blob/master/ofrak_core/tests/unit/packer_unpacker/test_unpack_pack_unpack.py) |

### 2. Analyze binary files
| Req ID | User Story (Requirement) | User Type | Validation |
|--------|--------------------------|-----------|------------|
| REQ2.1 | As an OFRAK contributor, I want to implement an analyzer using a well-defined interface so that it is easy to add new analyzers. | OFRAK Contributor | Analyzer interface is defined in [Analyzer][ofrak.component.analyzer]; analyzer test cases are defined in [analyzer_test_case](https://github.com/redballoonsecurity/ofrak/blob/master/ofrak_core/tests/unit/component/analyzer/analyzer_test_case.py) with an example test in [test_magic_analyzer](https://github.com/redballoonsecurity/ofrak/blob/master/ofrak_core/tests/unit/component/analyzer/test_magic_analyzer.py) |
| REQ2.2 | As an OFRAK user, I want access to a library of common analyzers so I can learn about an unknown binary. | OFRAK User | See the multiple analyzer tests in [tests/components](https://github.com/redballoonsecurity/ofrak/blob/master/ofrak_core/tests/components) |
| REQ2.3 | As an OFRAK user, I want to have parity across different combinations of disassembler backends: all common operations should be able to be performed with any backend combination. | OFRAK User | OFRAK supports the following backend combinations: Ghidra, Ghidra + Capstone, angr + Capstone. See : [test_unpackers (Angr)](https://github.com/redballoonsecurity/ofrak/blob/master/disassemblers/ofrak_angr/tests/test_unpackers.py), [test_unpackers (Ghidra)](https://github.com/redballoonsecurity/ofrak/blob/master/disassemblers/ofrak_ghidra/tests/test_unpackers.py), [test_ofrak_capstone](https://github.com/redballoonsecurity/ofrak/blob/master/disassemblers/ofrak_capstone/tests/test_ofrak_capstone.py)|
| REQ2.4 | As an OFRAK user, I want the analyzer outputs to be resource views and not attributes types, so that my class definition and types are cleaner and easier to read. | OFRAK User | The [Analyzer][ofrak.component.analyzer] interface supports analysis output of type `ViewableResourceTag` to allow for outputs to be of type `ResourceView` |

### 3. Modify binary files
| Req ID | User Story (Requirement) | User Type | Validation |
|--------|--------------------------|-----------|------------|
| REQ3.1 | As an OFRAK contributor, I want to implement a modifier using a well-defined interface so that it is easy to write new modifiers. | OFRAK Contributor | Modifier interface is defined in [Modifier][ofrak.component.modifier]; see the multiple modifier tests in [tests/components](https://github.com/redballoonsecurity/ofrak/blob/master/ofrak_core/tests/components) |
| REQ3.2 | As an OFRAK user, I want to extend a firmware image so that I have more space to inject bytes. | OFRAK User | [TestBinaryExtendModify](https://github.com/redballoonsecurity/ofrak/blob/master/ofrak_core/tests/components/test_binary.py) |
| REQ3.3 | As an OFRAK user, I want to mark regions of a binary as free space so that automated modifications can inject bytes there. | OFRAK User | [test_free_space_modifier](https://github.com/redballoonsecurity/ofrak/blob/master/ofrak_core/tests/components/test_free_space.py) and [test_allocate](https://github.com/redballoonsecurity/ofrak/blob/master/ofrak_core/tests/components/free_space_components_test/test_allocatable_allocate.py) |
| REQ3.4 | As an OFRAK user, I want access to a library of modifiers so that I can make common modifications quickly and easily. | OFRAK User | See the multiple modifier tests in [tests/components](https://github.com/redballoonsecurity/ofrak/blob/master/ofrak_core/tests/components) |

### 4. Pack binary files

| Req ID | User Story (Requirement) | User Type | Validation |
|--------|--------------------------|-----------|------------|
| REQ4.1 | As an OFRAK contributor, I want to implement a packer using a well-defined interface so that it is easy to write new packers. | OFRAK Contributor | Packer interface is defined in [Packer][ofrak.component.packer]; see the multiple packer tests in [tests/components](https://github.com/redballoonsecurity/ofrak/blob/master/ofrak_core/tests/components) |
| REQ4.2 | As an OFRAK user, I want to be able to repack an unpacked binary so that I can get a binary file that contains modifications. | OFRAK User | [test_unpack_pack_unpack](https://github.com/redballoonsecurity/ofrak/blob/master/ofrak_core/tests/unit/packer_unpacker/test_unpack_pack_unpack.py) |
| REQ4.3 | As an OFRAK user, I want to be able to recursively pack a nested tree of unpacked binaries. | OFRAK User | The recursive packing API (`Resource.pack_recursively`) is tested in [test_seven_zip_component](https://github.com/redballoonsecurity/ofrak/blob/master/ofrak_core/tests/components/test_seven_zip_component.py) |
| REQ4.4 | As an OFRAK user, I want access to a library of packers so I can perform packing on common file formats. | OFRAK User | See the multiple packer tests in [tests/components](https://github.com/redballoonsecurity/ofrak/blob/master/ofrak_core/tests/components) |

### 5. OFRAK Documentation
| Req ID | User Story (Requirement) | User Type | Validation |
|--------|--------------------------|-----------|------------|
| REQ5.1 | As an OFRAK user, I want an OFRAK Getting Started guide so that I can install OFRAK and run a simple script in 10 minutes. | OFRAK User | [Getting Started](../getting-started.md) |
| REQ5.2 | As an OFRAK user, I want to easily search the OFRAK documentation to learn how to use components that are already implemented. | OFRAK User | [OFRAK Docs](../index.md) are searchable |
| REQ5.3 | As an OFRAK user, I want documentation on how to configure OFRAK so that my OFRAK installation meets my needs. | OFRAK User | [OFRAK Installation Guide](../install/index.md) |
| REQ5.4 | As an OFRAK user, I want labs or tutorials demonstrating OFRAK so that I can learn how to use it. | OFRAK User | [Examples](../examples/examples/ex1_simple_string_modification.html) are available, along with [interactive tutorials](https://github.com/redballoonsecurity/ofrak/tree/master/ofrak_tutorial) |
| REQ5.5 | As an OFRAK contributor, I want tutorials in the OFRAK documentation on how to write each type of supported component so that I can implement a component quickly. | OFRAK Contributor | The [Contributor guide](./getting-started.md) has a Writing Components section |

## OFRAK Patch Maker Requirements
OFRAK Patch Maker requirements are encapsulated in the following Epic (6) and its user stories.

### 6. Assemble and compile source code into injectable payloads
| Req ID | User Story (Requirement) | User Type | Validation |
|--------|--------------------------|-----------|------------|
| REQ6.1 | As an OFRAK user, I want to be able to compile and link source code against specific addresses within a binary; I should be able to reference internal functions within the binary. | OFRAK User | [test_patch_maker_component](https://github.com/redballoonsecurity/ofrak/blob/master/ofrak_core/tests/components/test_patch_maker_component.py) |
| REQ6.2 | As an OFRAK user, I want to be able to carve code, writable data, and read-only data memory regions as injectable for the addresses in the linked binary. | OFRAK User | Handled by `SegmentInjectorModifierConfig.from_fem` used for example in `PatchFromSourceModifier` tested in [test_patch_from_source_modifier](https://github.com/redballoonsecurity/ofrak/blob/master/ofrak_core/tests/components/test_patch_from_source.py) |
