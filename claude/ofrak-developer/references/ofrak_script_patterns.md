# OFRAK Script Patterns

This document covers common patterns for writing standalone Python scripts that use the OFRAK library.

## Script Writing Workflow

When writing an OFRAK script, follow these steps:

1. **UNDERSTAND what script should do**
   - Define the goal clearly
   - Identify input files/parameters
   - Determine expected output

2. **CHECK references/ofrak_usage_guide.md for components**
   - Verify which components you'll need
   - Check component names and usage patterns
   - Understand configuration requirements

3. **VERIFY components exist (don't invent)**
   - Only use components documented in ofrak_usage_guide.md
   - Don't assume components exist based on naming patterns
   - Check OFRAK documentation if uncertain

4. **USE assets/script_template.py**
   - Start from the provided template
   - Follow the established structure
   - Include proper imports and argparse setup

5. **IMPLEMENT with proper async/await**
   - All OFRAK operations must use `await`
   - Main function must be `async def main(ofrak_context: OFRAKContext, ...)`
   - Use `ofrak.run(main, ...)` in `if __name__ == "__main__"`

6. **TEST script is valid Python**
   - Check syntax is correct
   - Verify all imports are available
   - Run with sample data if possible

7. **OUTPUT script to user**
   - Provide complete, runnable script
   - Include usage instructions
   - Show example invocation

## Basic Script Structure

All OFRAK scripts follow a consistent structure:

```python
"""
Brief description of what this script does.
"""
import argparse
from ofrak import OFRAK, OFRAKContext
# Import OFRAK components and views as needed

async def main(ofrak_context: OFRAKContext, arg1: str, arg2: int):
    """
    Main async function that performs the OFRAK operations.

    Args:
        ofrak_context: The OFRAK context for creating and managing resources
        arg1: Description of argument 1
        arg2: Description of argument 2
    """
    # Create root resource
    root_resource = await ofrak_context.create_root_resource_from_file(arg1)

    # Perform operations on the resource
    # ...

    # Save results if needed
    await root_resource.flush_data_to_disk("output.bin")

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Description of what the script does")
    parser.add_argument("input_file", help="Input binary file")
    parser.add_argument("--option", type=int, default=42, help="Optional parameter")
    args = parser.parse_args()

    # Create OFRAK instance and run
    ofrak = OFRAK()
    ofrak.run(main, args.input_file, args.option)
```

## Key Patterns

### 1. Creating Resources

**From a file:**
```python
root_resource = await ofrak_context.create_root_resource_from_file(file_path)
```

**From bytes:**
```python
data = b"\x7fELF..."
root_resource = await ofrak_context.create_root_resource(
    name="mybinary.bin",
    data=data
)
```

### 2. Unpacking Resources

**Basic unpacking:**
```python
# Automatically selects appropriate unpacker based on resource type
await root_resource.unpack()
```

**Recursive unpacking:**
```python
# Unpacks resource and all children
await root_resource.unpack_recursively()
```

### 3. Working with Resource Views

**Get a specific view:**
```python
from ofrak.core.elf.model import Elf

# View resource as ELF
elf = await root_resource.view_as(Elf)
print(f"Entry point: {hex(elf.header.e_entry)}")
```

**Check if resource has a tag:**
```python
from ofrak.core.elf.model import Elf

if root_resource.has_tag(Elf):
    elf = await root_resource.view_as(Elf)
    # Work with ELF
```

### 4. Accessing Children

**Get all children:**
```python
children = await root_resource.get_children()
for child in children:
    print(f"Child: {child.get_caption()}")
```

**Get children with specific tag:**
```python
from ofrak.core.filesystem import File

files = await root_resource.get_children_as_view(File)
for file in files:
    print(f"File: {file.name}, Size: {file.size}")
```

**Get descendants (children and grandchildren):**
```python
descendants = await root_resource.get_descendants()
```

### 5. Running Components

**Run a specific component:**
```python
from ofrak.core.strings import StringsAnalyzer

# Run component with default config
await root_resource.run(StringsAnalyzer)

# Access the results
strings = await root_resource.analyze(StringsAttributes)
for offset, string in strings.strings.items():
    print(f"{hex(offset)}: {string}")
```

**Run component with custom config:**
```python
from ofrak.core.strings import StringsAnalyzer, StringsAnalyzerConfig

config = StringsAnalyzerConfig(min_length=10)
await root_resource.run(StringsAnalyzer, config)
```

### 6. Modifying Resources

**Patch data at offset:**
```python
from ofrak.core.binary import BinaryPatchConfig, BinaryPatchModifier

config = BinaryPatchConfig(offset=0x1000, patch=b"\x90\x90\x90\x90")
await root_resource.run(BinaryPatchModifier, config)
```

**Search and replace:**
```python
from ofrak.core.strings import StringFindReplaceConfig, StringFindReplaceModifier

config = StringFindReplaceConfig(
    to_find=b"old_string",
    replace_with=b"new_string"
)
await root_resource.run(StringFindReplaceModifier, config)
```

### 7. Saving Results

**Save to file:**
```python
await root_resource.flush_data_to_disk("output.bin")
```

**Save child to file:**
```python
child = await root_resource.get_only_child()
await child.flush_data_to_disk("extracted_file.bin")
```

**Get data as bytes:**
```python
data = await root_resource.get_data()
print(f"Size: {len(data)} bytes")
```

### 8. Error Handling

**Handle missing components:**
```python
from ofrak.service.error import ComponentNotFoundError

try:
    await root_resource.run(SomeComponent)
except ComponentNotFoundError:
    print("Component not available, skipping...")
```

**Handle unpacking failures:**
```python
try:
    await root_resource.unpack()
except Exception as e:
    print(f"Failed to unpack: {e}")
    # Handle failure or continue
```

## Common Script Templates

### Analysis Script

```python
"""Analyze a binary and extract information."""
import argparse
from ofrak import OFRAK, OFRAKContext
from ofrak.core.strings import StringsAnalyzer

async def main(ofrak_context: OFRAKContext, binary_path: str):
    # Load binary
    root_resource = await ofrak_context.create_root_resource_from_file(binary_path)

    # Run analysis
    await root_resource.run(StringsAnalyzer)

    # Get results
    strings = await root_resource.analyze(StringsAttributes)
    print(f"Found {len(strings.strings)} strings")

    # Print strings
    for offset, string in sorted(strings.strings.items()):
        print(f"{hex(offset)}: {string}")

if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("binary", help="Binary file to analyze")
    args = parser.parse_args()

    ofrak = OFRAK()
    ofrak.run(main, args.binary)
```

### Unpacking Script

```python
"""Unpack an archive or firmware image."""
import argparse
from ofrak import OFRAK, OFRAKContext
from ofrak.core.filesystem import File

async def main(ofrak_context: OFRAKContext, archive_path: str, output_dir: str):
    # Load archive
    root_resource = await ofrak_context.create_root_resource_from_file(archive_path)

    # Recursively unpack
    await root_resource.unpack_recursively()

    # Extract all files
    files = await root_resource.get_descendants_as_view(File)

    for file in files:
        # Save each file
        output_path = f"{output_dir}/{file.name}"
        await file.resource.flush_data_to_disk(output_path)
        print(f"Extracted: {output_path}")

if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("archive", help="Archive to unpack")
    parser.add_argument("output_dir", help="Output directory")
    args = parser.parse_args()

    ofrak = OFRAK()
    ofrak.run(main, args.archive, args.output_dir)
```

### Patching Script

```python
"""Patch a binary at specific locations."""
import argparse
from ofrak import OFRAK, OFRAKContext
from ofrak.core.binary import BinaryPatchConfig, BinaryPatchModifier

async def main(ofrak_context: OFRAKContext, binary_path: str, output_path: str):
    # Load binary
    root_resource = await ofrak_context.create_root_resource_from_file(binary_path)

    # Apply patches
    patches = [
        (0x1000, b"\x90\x90\x90\x90"),  # NOP at 0x1000
        (0x2000, b"\xc3"),              # RET at 0x2000
    ]

    for offset, patch_data in patches:
        config = BinaryPatchConfig(offset=offset, patch=patch_data)
        await root_resource.run(BinaryPatchModifier, config)
        print(f"Patched at {hex(offset)}: {patch_data.hex()}")

    # Save patched binary
    await root_resource.flush_data_to_disk(output_path)
    print(f"Saved to: {output_path}")

if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("input", help="Input binary")
    parser.add_argument("output", help="Output patched binary")
    args = parser.parse_args()

    ofrak = OFRAK()
    ofrak.run(main, args.input, args.output)
```

## Best Practices

1. **Always use async/await**: OFRAK operations are asynchronous
2. **Use argparse for CLI**: Makes scripts more usable and professional
3. **Include docstrings**: Document what the script does and its parameters
4. **Handle errors gracefully**: Don't let exceptions crash your script
5. **Clean up resources**: OFRAK handles this automatically when using `ofrak.run()`
6. **Use type hints**: Makes code clearer and catches errors earlier
7. **Keep scripts focused**: One script = one task
8. **Use meaningful variable names**: `root_resource` not just `r`
9. **Print progress**: Let users know what's happening
10. **Validate inputs**: Check file paths, ranges, etc. before processing

## Common Imports

```python
# Core OFRAK
from ofrak import OFRAK, OFRAKContext

# Binary operations
from ofrak.core.binary import BinaryPatchConfig, BinaryPatchModifier

# Strings
from ofrak.core.strings import (
    StringsAnalyzer,
    StringsAttributes,
    StringFindReplaceConfig,
    StringFindReplaceModifier
)

# File formats
from ofrak.core.elf.model import Elf
from ofrak.core.pe.model import Pe
from ofrak.core.filesystem import File, Folder, FilesystemRoot

# Archives
from ofrak.core.zip import ZipArchive
from ofrak.core.tar import TarArchive

# Code analysis
from ofrak.core.code_region import CodeRegion
from ofrak.core.basic_block import BasicBlock
from ofrak.core.instruction import Instruction
```

## Discovering Available Components

When writing a script, you may need to find which components are available:

```python
# List all available components
from ofrak.service.component_locator import ComponentLocator

locator = ComponentLocator()
components = locator.get_components_matching_filter()

for component in components:
    print(f"{component.get_id()}: {component.__doc__}")
```

For detailed information about specific components, refer to the OFRAK documentation in the `ofrak/docs/` directory of the cloned repository.
