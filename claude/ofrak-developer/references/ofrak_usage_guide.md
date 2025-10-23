# OFRAK Usage Guide

This guide explains how to effectively use OFRAK components in standalone Python scripts.

## Understanding OFRAK Components

OFRAK provides four main types of components:

1. **Identifiers** - Detect file types and formats
2. **Analyzers** - Extract information from resources
3. **Unpackers** - Extract embedded content (files, sections, etc.)
4. **Modifiers** - Modify resources (patch, inject, etc.)

## Component Discovery

### Finding Available Components

OFRAK automatically discovers and selects appropriate components based on resource type. You generally don't need to manually specify which unpacker or identifier to use.

**Automatic component selection:**
```python
# OFRAK automatically detects file type
root_resource = await ofrak_context.create_root_resource_from_file("firmware.bin")

# OFRAK automatically selects appropriate unpacker
await root_resource.unpack()
```

**Manual component execution:**
```python
# Run a specific analyzer
from ofrak.core.strings import StringsAnalyzer
await root_resource.run(StringsAnalyzer)
```

### Understanding Component Requirements

Components have **targets** - the resource types they can operate on. OFRAK ensures components only run on appropriate resources.

**Example:**
- `ElfUnpacker` targets `Elf` resources
- `StringsAnalyzer` can target any binary resource
- `BinaryPatchModifier` targets binary data

## Working with Different File Formats

### ELF Binaries

```python
from ofrak.core.elf.model import Elf, ElfSection, ElfSegment

# Load and view as ELF
root_resource = await ofrak_context.create_root_resource_from_file("binary.elf")
elf = await root_resource.view_as(Elf)

# Access ELF header info
print(f"Entry point: {hex(elf.header.e_entry)}")
print(f"Architecture: {elf.header.e_machine}")

# Unpack to get sections and segments
await root_resource.unpack()

# Get all sections
sections = await root_resource.get_children_as_view(ElfSection)
for section in sections:
    print(f"Section: {section.name} at {hex(section.virtual_address)}")
```

### PE Binaries

```python
from ofrak.core.pe.model import Pe

# Load and view as PE
root_resource = await ofrak_context.create_root_resource_from_file("binary.exe")
pe = await root_resource.view_as(Pe)

# Access PE info
print(f"Machine type: {pe.machine_type}")
print(f"Entry point: {hex(pe.entry_point)}")
```

### Archives (ZIP, TAR, etc.)

```python
from ofrak.core.zip import ZipArchive
from ofrak.core.filesystem import File

# Load archive
root_resource = await ofrak_context.create_root_resource_from_file("archive.zip")

# Unpack archive
await root_resource.unpack()

# Get all files
files = await root_resource.get_children_as_view(File)
for file in files:
    print(f"File: {file.name}, Size: {file.size}")
    data = await file.resource.get_data()
    # Process file data
```

### Filesystem Images

```python
from ofrak.core.filesystem import FilesystemRoot, File, Folder

# Load filesystem image
root_resource = await ofrak_context.create_root_resource_from_file("filesystem.img")

# Unpack filesystem
await root_resource.unpack_recursively()

# Navigate filesystem structure
fs_root = await root_resource.get_only_child_as_view(FilesystemRoot)

# Find specific files
descendants = await root_resource.get_descendants()
for desc in descendants:
    if desc.has_tag(File):
        file = await desc.view_as(File)
        if file.name.endswith(".conf"):
            print(f"Found config: {file.name}")
```

## Common Analysis Tasks

### String Extraction

```python
from ofrak.core.strings import StringsAnalyzer, StringsAttributes

# Run strings analysis
await root_resource.run(StringsAnalyzer)

# Get results
strings_attr = await root_resource.analyze(StringsAttributes)

# Print strings with offsets
for offset, string in sorted(strings_attr.strings.items()):
    print(f"{hex(offset)}: {string}")

# Filter strings
long_strings = {off: s for off, s in strings_attr.strings.items() if len(s) > 20}
```

### Code Analysis

```python
from ofrak.core.code_region import CodeRegion
from ofrak.core.basic_block import BasicBlock
from ofrak.core.instruction import Instruction

# Unpack to get code regions
await root_resource.unpack_recursively()

# Find all basic blocks
blocks = await root_resource.get_descendants_as_view(BasicBlock)

for block in blocks:
    print(f"Basic block at {hex(block.virtual_address)}, size: {block.size}")

    # Get instructions in block
    instructions = await block.resource.get_children_as_view(Instruction)
    for instr in instructions:
        print(f"  {hex(instr.virtual_address)}: {instr.mnemonic} {instr.operands}")
```

### Memory Mapping Analysis

```python
from ofrak.core.memory_region import MemoryRegion

# Get memory regions
regions = await root_resource.get_descendants_as_view(MemoryRegion)

for region in regions:
    print(f"Region: {hex(region.virtual_address)} - {hex(region.virtual_address + region.size)}")
    print(f"  Permissions: {'R' if region.readable else '-'}{'W' if region.writable else '-'}{'X' if region.executable else '-'}")
```

## Common Modification Tasks

### Binary Patching

```python
from ofrak.core.binary import BinaryPatchConfig, BinaryPatchModifier

# Patch at specific offset
config = BinaryPatchConfig(offset=0x1000, patch=b"\x90" * 4)
await root_resource.run(BinaryPatchModifier, config)
```

### String Replacement

```python
from ofrak.core.strings import StringFindReplaceConfig, StringFindReplaceModifier

# Replace string (must be same length or shorter)
config = StringFindReplaceConfig(
    to_find=b"debug_mode_off",
    replace_with=b"debug_mode_on\x00"
)
await root_resource.run(StringFindReplaceModifier, config)
```

### Code Modification

```python
from ofrak.core.instruction import Instruction
from ofrak.core.binary import BinaryPatchModifier, BinaryPatchConfig

# Find instruction to patch
instructions = await root_resource.get_descendants_as_view(Instruction)
for instr in instructions:
    if instr.mnemonic == "jne" and instr.virtual_address == 0x401234:
        # Change jne to jmp (example)
        patch_offset = instr.virtual_address - base_address
        config = BinaryPatchConfig(offset=patch_offset, patch=b"\xeb")
        await root_resource.run(BinaryPatchModifier, config)
        break
```

## Resource Navigation

### Finding Specific Resources

```python
# Find by tag
from ofrak.core.elf.model import ElfSection

sections = await root_resource.get_descendants_as_view(ElfSection)

# Find specific section
text_section = None
for section in sections:
    if section.name == ".text":
        text_section = section
        break

if text_section:
    print(f".text section at {hex(text_section.virtual_address)}")
```

### Working with Resource Hierarchy

```python
# Get immediate children only
children = await root_resource.get_children()

# Get all descendants (children, grandchildren, etc.)
descendants = await root_resource.get_descendants()

# Get parent
child = children[0]
parent = await child.get_parent()

# Get ancestors
ancestors = await child.get_ancestors()
```

### Filtering Resources

```python
# Get only resources with specific tag
from ofrak.core.filesystem import File

files = [r for r in await root_resource.get_descendants() if r.has_tag(File)]

# Filter by attribute
large_files = []
for file_resource in files:
    file_view = await file_resource.view_as(File)
    if file_view.size > 1024 * 1024:  # > 1MB
        large_files.append(file_view)
```

## Configuration Options

### Component Configs

Many components accept configuration to customize behavior:

```python
from ofrak.core.strings import StringsAnalyzer, StringsAnalyzerConfig

# Custom min length for strings
config = StringsAnalyzerConfig(min_length=10)
await root_resource.run(StringsAnalyzer, config)
```

### OFRAK Context Options

```python
# Create OFRAK with custom options
ofrak = OFRAK()

# Register custom components
ofrak.discover(MyCustomComponent)

# Run with context
await ofrak.run(main, arg1, arg2)
```

## Error Handling Best Practices

### Handle Missing Components

```python
from ofrak.service.error import ComponentNotFoundError

try:
    await root_resource.run(SomeOptionalComponent)
except ComponentNotFoundError:
    print("Component not available, using fallback")
    # Use alternative approach
```

### Handle Unpacking Failures

```python
try:
    await root_resource.unpack()
except Exception as e:
    print(f"Warning: Failed to unpack {root_resource.get_caption()}: {e}")
    # Continue with analysis on packed data
```

### Validate Resource State

```python
# Check if resource has expected tag before using view
from ofrak.core.elf.model import Elf

if root_resource.has_tag(Elf):
    elf = await root_resource.view_as(Elf)
    # Safe to use ELF-specific operations
else:
    print("Not an ELF file")
```

## Performance Considerations

### Recursive Operations

```python
# For deep unpacking, use unpack_recursively
await root_resource.unpack_recursively()

# For controlled unpacking, manually iterate
await root_resource.unpack()
children = await root_resource.get_children()
for child in children:
    if should_unpack(child):
        await child.unpack()
```

### Resource Querying

```python
# Efficient: Get specific children
text_sections = await root_resource.get_children_as_view(
    ElfSection,
    r_filter=lambda r: r.name == ".text"
)

# Less efficient: Get all then filter in Python
all_sections = await root_resource.get_children_as_view(ElfSection)
text_sections = [s for s in all_sections if s.name == ".text"]
```

## Debugging Scripts

### Print Resource Information

```python
# Print resource tree
def print_tree(resource, indent=0):
    print("  " * indent + resource.get_caption())
    children = await resource.get_children()
    for child in children:
        await print_tree(child, indent + 1)

await print_tree(root_resource)
```

### Inspect Resource Attributes

```python
# Get all attributes
attributes = await root_resource.get_attributes()
for attr_type, attr in attributes.items():
    print(f"{attr_type.__name__}: {attr}")
```

### Enable Logging

```python
import logging

# Enable OFRAK debug logging
logging.basicConfig(level=logging.DEBUG)
```

## Reference Documentation

For comprehensive API documentation, see the cloned OFRAK repository:
- **OFRAK User Guide**: `ofrak/docs/user-guide/` directory
- **OFRAK API Reference**: `ofrak/docs/reference/` directory
- **Example Scripts**: `ofrak/examples/` directory

If you don't have the OFRAK repository cloned, instruct the user to clone it: `git clone https://github.com/redballoonsecurity/ofrak.git`

## Getting Help

- **OFRAK Documentation**: Available in `ofrak/docs/` of the cloned repository
- **GitHub Issues**: https://github.com/redballoonsecurity/ofrak/issues
- **Slack Community**: https://join.slack.com/t/ofrak/shared_invite/zt-1jku9h6r5-mY7CeeZ4AT8JVmu5YWw2Qg
