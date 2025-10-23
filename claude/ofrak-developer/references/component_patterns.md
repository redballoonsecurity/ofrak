# OFRAK Component Patterns

This document covers common patterns for implementing OFRAK components (Identifiers, Analyzers, Unpackers, Modifiers, and Packers).

## Component Base Classes

OFRAK provides five main component types:

1. **Identifier** - Detects resource types and adds appropriate tags
2. **Analyzer** - Extracts information and creates attributes
3. **Unpacker** - Extracts embedded content and creates child resources
4. **Modifier** - Modifies resources (patches, injections, etc.)
5. **Packer** - Packs/compresses resources

## Understanding Component Types

**CRITICAL: Deep understanding of when to use each component type.**

Choosing the wrong component type will cause implementation issues. This section provides detailed guidance for each type.

### Identifier

**Purpose**: Detect and tag resource types based on file signatures, magic bytes, or structure.

**When to use**:
- Need to recognize a new file format
- Detect specific file types (ELF, PE, ZIP, etc.)
- Add tags to resources without extracting data

**Key characteristics**:
- Reads data to check signatures/structure
- Adds tags using `resource.add_tag(TagClass)`
- Does NOT create attributes or children
- Does NOT modify data
- Typically has empty `targets` tuple (runs on unidentified resources)

**Example use cases**:
- Identify ZIP files by checking `PK\x03\x04` signature
- Detect ELF binaries by checking magic number `\x7fELF`
- Recognize custom firmware formats

**Common mistakes**:
- Don't use Identifier to extract metadata - use Analyzer for that
- Don't create children in Identifier - use Unpacker for that

### Analyzer

**Purpose**: Extract information and metadata from resources, creating attributes.

**When to use**:
- Need to parse headers or metadata
- Extract configuration or properties
- Gather information without changing the resource

**Key characteristics**:
- Returns `ResourceAttributes` with extracted data
- Does NOT create child resources
- Does NOT modify data
- Defines `targets` (what resource types it analyzes)
- Defines `outputs` (what attributes it produces)

**Example use cases**:
- Parse ELF header to extract entry point, architecture, sections
- Extract ZIP metadata (compression method, file count)
- Analyze PE headers for imports/exports
- Extract firmware version information
- Parse configuration data from binaries

**Common mistakes**:
- Don't use Analyzer to create children - that's Unpacker's job
- Don't modify resource data in Analyzer - use Modifier for that
- Don't tag resources in Analyzer - use Identifier for that

### Unpacker

**Purpose**: Extract embedded content, creating child resources.

**When to use**:
- Need to extract files from archives
- Decompress or decrypt embedded data
- Split a resource into meaningful parts (sections, segments, etc.)

**Key characteristics**:
- Creates child resources using `await resource.create_child()`
- Does NOT return attributes (use Analyzer for that)
- Does NOT modify parent data
- Defines `targets` (what resource types it unpacks)
- Defines `children` (what types of children it creates)

**Example use cases**:
- Extract files from ZIP/TAR archives
- Unpack ELF sections and segments
- Extract firmware partitions
- Decompress LZMA/GZIP data
- Extract embedded filesystems

**Common mistakes**:
- Don't modify parent data in Unpacker - use Modifier for that
- Don't return attributes in Unpacker - use Analyzer for that
- Don't forget to tag children appropriately (use `tags=(File,)` etc.)

### Modifier

**Purpose**: Modify resource data (patch, inject, transform).

**When to use**:
- Need to patch bytes at specific offsets
- Replace strings or values
- Inject code or data
- Transform data in-place

**Key characteristics**:
- Uses `resource.queue_patch()` to queue modifications (NOT async)
- Must call `await resource.save()` to apply queued patches
- Does NOT create children
- Does NOT return attributes
- Takes configuration specifying what to modify
- Defines `targets` (what resource types it can modify)

**Example use cases**:
- Patch bytes at offset (NOP instructions, change values)
- Replace strings in binaries
- Inject shellcode or payloads
- Change configuration values
- Modify firmware checksums

**Common mistakes**:
- Must use `queue_patch()`, not direct data modification
- Don't forget to call `await resource.save()` after queueing patches
- Don't create children in Modifier - use Unpacker for that
- Don't forget to handle offset calculations correctly

### Packer

**Purpose**: Reconstruct parent resource from modified children (reverse of Unpacker).

**When to use**:
- Need to rebuild archive after modifying extracted files
- Recompress data after changes
- Reconstruct binary format after child modifications

**Key characteristics**:
- Reads children and rebuilds parent data
- Uses `resource.queue_patch()` to queue updates (NOT async)
- Must call `await resource.save()` to apply queued patches
- Pairs with corresponding Unpacker
- Defines `targets` (what resource types it packs)

**Example use cases**:
- Rebuild ZIP archive after modifying files
- Reconstruct ELF after modifying sections
- Recompress firmware after patches
- Pack squashfs after file changes
- Rebuild TAR archives

**Common mistakes**:
- Packer is NOT always needed - only when format requires reconstruction
- Must match the structure created by corresponding Unpacker
- Don't forget to update checksums/sizes if format requires them

### Quick Reference Table

| Component Type | Creates Children | Returns Attributes | Modifies Data | Primary Use |
|---------------|------------------|-------------------|---------------|-------------|
| **Identifier** | ❌ | ❌ | ❌ | Detect file format |
| **Analyzer** | ❌ | ✅ | ❌ | Extract metadata |
| **Unpacker** | ✅ | ❌ | ❌ | Extract content |
| **Modifier** | ❌ | ❌ | ✅ | Patch/transform |
| **Packer** | ❌ | ❌ | ✅ | Rebuild from children |

## Component Development Workflow

When adding a new component (using Unpacker as example), follow these steps:

1. **READ contributor documentation (MANDATORY)**
   - Read `ofrak/docs/contributor-guide/getting-started.md`
   - Read component-specific guide: `ofrak/docs/contributor-guide/component/unpacker.md`

2. **SEARCH for similar components**
   - Use Glob to find similar implementations: `Glob("**/zip*.py")`, `Glob("**/tar*.py")`
   - Search for components of the same type
   - Look for similar file formats or functionality

3. **READ similar unpacker implementation**
   - Study how existing components are structured
   - Note patterns: how they create children, handle errors, tag resources
   - Understand the coding style and conventions

4. **USE assets/component_template.py as starting point**
   - Start from the provided template
   - Follow structure from similar components
   - Adapt template to your specific needs

5. **IMPLEMENT unpacker following patterns**
   - Follow structure from documentation and similar components
   - Define `targets` (what resource types to unpack)
   - Define `children` (what types of children are created)
   - Use `await resource.create_child()` to create children
   - Tag children appropriately

6. **CREATE TESTS AUTOMATICALLY**
   - Use `assets/test_template.py` as starting point
   - Follow patterns from `references/testing_patterns.md`
   - Test with real binary data (not mocks)
   - Cover edge cases: empty archives, corrupted data, large files

7. **ENSURE 100% coverage**
   - Execute: `pytest path/to/test_file.py -v --cov=module_name`
   - Fix any failures
   - Add tests until all code paths are covered

8. **CREATE example script (output to console)**
   - Write example usage showing practical application
   - Follow patterns from `ofrak/examples/`
   - Output to console, don't create a file
   - Show how to use the new component

9. **UPDATE changelog with #PLACEHOLDER**
   - Find appropriate CHANGELOG.md (likely `ofrak_core/CHANGELOG.md`)
   - Add entry under "Added" section
   - Format: `- Add support for XYZ format unpacking ([#PLACEHOLDER](...)`

10. **READ ofrak/.github/pull_request_template.md**
    - Read the actual PR template from the file
    - Don't hardcode or assume format

11. **FILL and OUTPUT PR template for easy copy/paste**
    - Fill in all sections concisely (5-7 sentences max)
    - Include links to related issues or "N/A"
    - Output to console for easy copying
    - Remind user to update #PLACEHOLDER with actual PR number

**Note**: These steps apply to all component types (Identifier, Analyzer, Unpacker, Modifier, Packer). Adjust step 1 to read the appropriate component-specific guide.

## General Component Structure

All components follow this basic pattern:

```python
from dataclasses import dataclass
from ofrak.component.abstract import ComponentSubprocessRunner
from ofrak.resource import Resource
from ofrak.model.component_model import ComponentConfig

@dataclass
class MyComponentConfig(ComponentConfig):
    """Configuration for MyComponent."""
    option1: str
    option2: int = 42  # Default value

class MyComponent(ComponentSubprocessRunner):
    """
    Brief description of what this component does.

    Detailed explanation of component behavior, requirements, etc.
    """

    # Component metadata (id must be bytes)
    id = b"MyComponent"

    async def run(self, resource: Resource, config: MyComponentConfig) -> None:
        """
        Execute the component logic.

        Args:
            resource: The resource to operate on
            config: Component configuration
        """
        # Implementation here
```

## Identifier Pattern

Identifiers detect resource types and add appropriate tags.

```python
from ofrak.component.identifier import Identifier
from ofrak.resource import Resource
from ofrak.core.magic import MagicMimeIdentifier, MagicDescriptionIdentifier

class MyFormatIdentifier(Identifier):
    """
    Identify MyFormat files by checking file signature.
    """

    id = b"MyFormatIdentifier"

    # Identifiers to run before this one
    # This ensures magic has been run to get basic file info
    targets = ()

    async def identify(self, resource: Resource, config=None) -> None:
        """
        Identify MyFormat files and add MyFormat tag.

        Args:
            resource: Resource to identify
            config: Unused
        """
        # Get file data
        data = await resource.get_data()

        # Check for MyFormat signature (magic bytes)
        if data[:4] == b"MYFT":
            # Add the tag
            resource.add_tag(MyFormat)
```

**Key points:**
- Inherit from `Identifier`
- Implement `identify()` method
- Add tags using `resource.add_tag(TagClass)`
- Check file signatures, magic numbers, or structure
- Don't create attributes or children (that's for Analyzers/Unpackers)

## Analyzer Pattern

Analyzers extract information and create attributes.

```python
from dataclasses import dataclass
from ofrak.component.analyzer import Analyzer
from ofrak.model.resource_model import ResourceAttributes
from ofrak.resource import Resource

@dataclass
class MyFormatAttributes(ResourceAttributes):
    """Attributes for MyFormat resources."""
    version: int
    compression_type: str
    entry_count: int

class MyFormatAnalyzer(Analyzer[None, MyFormatAttributes]):
    """
    Analyze MyFormat files and extract metadata.
    """

    id = b"MyFormatAnalyzer"
    targets = (MyFormat,)  # Only run on MyFormat resources
    outputs = (MyFormatAttributes,)  # What this analyzer produces

    async def analyze(self, resource: Resource, config=None) -> MyFormatAttributes:
        """
        Extract MyFormat metadata.

        Args:
            resource: MyFormat resource to analyze
            config: Unused

        Returns:
            MyFormatAttributes with extracted metadata
        """
        data = await resource.get_data()

        # Parse header
        version = int.from_bytes(data[4:6], "little")
        compression_type = data[6:10].decode("ascii")
        entry_count = int.from_bytes(data[10:14], "little")

        return MyFormatAttributes(
            version=version,
            compression_type=compression_type,
            entry_count=entry_count
        )
```

**Key points:**
- Inherit from `Analyzer[ConfigType, OutputAttributeType]`
- Define `targets` - what resource types this analyzer applies to
- Define `outputs` - what attributes this analyzer produces
- Implement `analyze()` method that returns attributes
- Don't modify resource or create children

## Unpacker Pattern

Unpackers extract embedded content and create child resources.

```python
from ofrak.component.unpacker import Unpacker
from ofrak.resource import Resource
from ofrak.core.filesystem import File

class MyFormatUnpacker(Unpacker[None]):
    """
    Unpack MyFormat archives and extract contained files.
    """

    id = b"MyFormatUnpacker"
    targets = (MyFormat,)  # Only run on MyFormat resources
    children = (File,)  # What types of children this creates

    async def unpack(self, resource: Resource, config=None) -> None:
        """
        Extract files from MyFormat archive.

        Args:
            resource: MyFormat archive resource
            config: Unused
        """
        data = await resource.get_data()

        # Get format attributes (assumes analyzer ran first)
        attrs = await resource.analyze(MyFormatAttributes)

        # Parse entries
        offset = 14  # After header
        for i in range(attrs.entry_count):
            # Read entry metadata
            name_len = int.from_bytes(data[offset:offset+2], "little")
            offset += 2
            name = data[offset:offset+name_len].decode("utf-8")
            offset += name_len

            file_size = int.from_bytes(data[offset:offset+4], "little")
            offset += 4

            # Extract file data
            file_data = data[offset:offset+file_size]
            offset += file_size

            # Create child resource for this file
            await resource.create_child(
                tags=(File,),
                data=file_data,
                attributes=(File(name, file_size),)
            )
```

**Key points:**
- Inherit from `Unpacker[ConfigType]`
- Define `targets` - what this unpacker can unpack
- Define `children` - what types of children it creates
- Implement `unpack()` method
- Create children using `resource.create_child()`
- Can use attributes from analyzers

## Modifier Pattern

Modifiers change resource data.

```python
from dataclasses import dataclass
from ofrak.component.modifier import Modifier
from ofrak.model.component_model import ComponentConfig
from ofrak.resource import Resource

@dataclass
class MyModifierConfig(ComponentConfig):
    """Configuration for MyModifier."""
    target_string: bytes
    replacement: bytes

class MyModifier(Modifier[MyModifierConfig]):
    """
    Replace occurrences of a string in MyFormat resources.
    """

    id = b"MyModifier"
    targets = (MyFormat,)

    async def modify(self, resource: Resource, config: MyModifierConfig) -> None:
        """
        Replace target string with replacement in resource data.

        Args:
            resource: Resource to modify
            config: Modification configuration
        """
        # Get current data
        data = await resource.get_data()

        # Perform modification
        modified_data = data.replace(config.target_string, config.replacement)

        # Queue modification (NOT async)
        resource.queue_patch(Range(0, len(data)), modified_data)

        # Apply the patch (required!)
        await resource.save()
```

**Key points:**
- Inherit from `Modifier[ConfigType]`
- Define `targets` - what this modifier can modify
- Implement `modify()` method
- Use `resource.queue_patch()` to queue modifications (NOT async)
- Call `await resource.save()` to apply queued patches
- Don't directly write data - use patching system

## Packer Pattern

Packers compress or pack resources (reverse of unpackers).

```python
from ofrak.component.packer import Packer
from ofrak.resource import Resource
from ofrak.core.filesystem import File

class MyFormatPacker(Packer[None]):
    """
    Pack files into MyFormat archive.
    """

    id = b"MyFormatPacker"
    targets = (MyFormat,)

    async def pack(self, resource: Resource, config=None) -> None:
        """
        Pack child files into MyFormat archive format.

        Args:
            resource: MyFormat resource with children to pack
            config: Unused
        """
        # Get all file children
        children = await resource.get_children_as_view(File)

        # Build header
        header = bytearray(b"MYFT")  # Magic
        header.extend((1).to_bytes(2, "little"))  # Version
        header.extend(b"NONE")  # Compression type
        header.extend(len(children).to_bytes(4, "little"))  # Entry count

        # Build entries
        entries = bytearray()
        for child_file in children:
            # Get file data
            child_data = await child_file.resource.get_data()

            # Write entry
            name_bytes = child_file.name.encode("utf-8")
            entries.extend(len(name_bytes).to_bytes(2, "little"))
            entries.extend(name_bytes)
            entries.extend(len(child_data).to_bytes(4, "little"))
            entries.extend(child_data)

        # Combine and queue patch (NOT async)
        packed_data = bytes(header + entries)
        original_size = await resource.get_data_length()
        resource.queue_patch(Range(0, original_size), packed_data)

        # Apply the patch (required!)
        await resource.save()
```

**Key points:**
- Inherit from `Packer[ConfigType]`
- Define `targets` - what this packer can pack
- Implement `pack()` method
- Reconstruct parent data from children
- Use `resource.queue_patch()` to queue updates (NOT async)
- Call `await resource.save()` to apply queued patches

## External Tool Integration

**IMPORTANT: When adding external dependencies, see `contributing_guidelines.md` → "Dependency Management" section.**

- **Python dependencies** → Update package's `requirements.txt` (pinned to latest stable version)
- **Apt dependencies** → Update package's `Dockerstub`
- **Avoid** dependencies requiring build from source

For components that use external tools:

```python
from ofrak.component.abstract import ComponentSubprocessRunner
from ofrak.core.binary import GenericBinary
import tempfile
import subprocess

class MyExternalToolComponent(ComponentSubprocessRunner):
    """
    Component that uses an external tool.
    """

    id = b"MyExternalToolComponent"
    targets = (GenericBinary,)

    # External dependencies
    external_dependencies = ("my-external-tool",)

    async def run(self, resource: Resource, config=None) -> None:
        """
        Run external tool on resource.

        Args:
            resource: Resource to process
            config: Unused
        """
        # Write data to temp file
        with tempfile.NamedTemporaryFile(suffix=".bin", delete=False) as f:
            temp_path = f.name
            data = await resource.get_data()
            f.write(data)

        try:
            # Run external tool
            result = subprocess.run(
                ["my-external-tool", "--option", temp_path],
                capture_output=True,
                check=True
            )

            # Process results
            output = result.stdout.decode("utf-8")
            # ... handle output ...

        finally:
            # Clean up temp file
            import os
            os.unlink(temp_path)
```

**Key points:**
- Inherit from `ComponentSubprocessRunner` for external tools
- Declare `external_dependencies` tuple
- **CRITICAL: Only use cross-platform external tools (macOS/Linux/Windows compatible)**
- Perform pro/con analysis before choosing Python vs external tool
- Use `tempfile` for temporary file I/O
- Always clean up temporary files
- Handle subprocess errors properly

## Choosing Between Pure Python vs External Tools

**When deciding implementation approach, analyze trade-offs:**

### Use External Tool When:
- ✅ Tool is widely used and well-tested (e.g., `7z`, `squashfs-tools`)
- ✅ Format is complex (filesystems, compression algorithms)
- ✅ Tool is cross-platform (available on macOS/Linux/Windows)
- ✅ Tool has stable API/output format
- ✅ Performance is critical (native code often faster)
- ✅ Reimplementation would be error-prone

**Examples**: `7z` for archives, `unsquashfs` for SquashFS, `e2fsprogs` for ext2/3/4

### Use Pure Python When:
- ✅ Format is simple or well-documented
- ✅ Good Python libraries exist (e.g., `zipfile`, `tarfile`)
- ✅ No suitable cross-platform external tool available
- ✅ External tool would add heavy dependency
- ✅ Need fine-grained control over parsing
- ✅ Easier testing and debugging

**Examples**: ZIP (use `zipfile`), TAR (use `tarfile`), JSON parsing

### Cross-Platform Requirements:
**External tools MUST work on all three platforms:**
- macOS
- Linux (various distributions)
- Windows

**How to verify cross-platform compatibility:**
1. Check if tool is in standard package managers:
   - macOS: Homebrew (`brew`)
   - Linux: apt, yum, pacman
   - Windows: chocolatey, scoop
2. Test on multiple platforms or research tool availability
3. Document installation requirements in component docstring

**Red flags (avoid these):**
- ❌ Linux-only tools without Windows/macOS alternatives
- ❌ Platform-specific utilities (`dd`, `losetup` without alternatives)
- ❌ Tools requiring kernel modules or drivers
- ❌ Tools with incompatible versions across platforms

## Resource View Pattern

Resource views provide convenient access to resources with specific tags:

```python
from dataclasses import dataclass
from ofrak.model.resource_model import ResourceAttributes
from ofrak.resource_view import ResourceView
from ofrak.core.addressable import Addressable

@dataclass
class MyFormatAttributes(ResourceAttributes):
    version: int
    entry_count: int

class MyFormat(ResourceView):
    """
    View for MyFormat resources.

    Provides convenient access to MyFormat-specific attributes.
    """

    # Required views that this view depends on
    # Empty if no dependencies
    view_dependencies = ()

    # Attributes this view uses
    # Can be retrieved with self.<attribute_field>

    async def get_version(self) -> int:
        """Get MyFormat version."""
        attrs = await self.resource.analyze(MyFormatAttributes)
        return attrs.version

    async def extract_entry(self, index: int) -> bytes:
        """
        Extract specific entry by index.

        Args:
            index: Entry index to extract

        Returns:
            Entry data as bytes
        """
        # Implementation
        pass
```

## Common Patterns

### Pattern: Checking Dependencies

```python
async def analyze(self, resource: Resource, config=None):
    # Ensure required analyzer has run
    if not resource.has_attributes(RequiredAttributes):
        await resource.analyze(RequiredAttributes)

    required_attrs = await resource.analyze(RequiredAttributes)
    # Use required_attrs...
```

### Pattern: Creating Tagged Children

```python
# Create child with multiple tags
await resource.create_child(
    tags=(File, ExecutableFile),
    data=file_data,
    attributes=(
        File(name="binary.elf", size=len(file_data)),
    )
)
```

### Pattern: Handling Errors Gracefully

```python
try:
    result = external_tool_call()
except subprocess.CalledProcessError as e:
    raise ComponentError(
        f"External tool failed: {e.stderr.decode()}"
    )
```

### Pattern: Lazy Attribute Access

```python
class MyFormat(ResourceView):
    async def get_header(self):
        """Get header (cached after first access)."""
        if not hasattr(self, "_header"):
            data = await self.resource.get_data(Range(0, 16))
            self._header = parse_header(data)
        return self._header
```

## Testing Components

Every component needs comprehensive tests. See `testing_patterns.md` for details.

## Component Registration

Components are automatically discovered by OFRAK if they're in the right packages. For custom components:

```python
from ofrak import OFRAK

ofrak = OFRAK()
ofrak.discover(MyCustomComponent)
```

## Best Practices

1. **Single Responsibility**: Each component should do one thing well
2. **Clear Targets**: Define precise targets to avoid running on wrong resources
3. **Proper Dependencies**: Use `view_dependencies` and check required attributes
4. **Error Handling**: Raise appropriate exceptions with clear messages
5. **Documentation**: Include comprehensive docstrings
6. **Testing**: Write tests for all code paths (100% coverage required)
7. **Type Annotations**: Use proper type hints throughout
8. **Efficient Data Access**: Use ranges when reading specific offsets
9. **Clean External Tools**: Always clean up temporary files
10. **Follow Patterns**: Look at similar existing components for patterns

## Reference Implementation Examples

For real examples of each component type, examine these files in the OFRAK repository:

- **Identifiers**: `ofrak_core/ofrak/core/zip.py` (ZipIdentifier)
- **Analyzers**: `ofrak_core/ofrak/core/elf/model.py` (ElfAnalyzer)
- **Unpackers**: `ofrak_core/ofrak/core/zip.py` (ZipUnpacker)
- **Modifiers**: `ofrak_core/ofrak/core/binary.py` (BinaryPatchModifier)
- **Packers**: `ofrak_core/ofrak/core/zip.py` (ZipPacker)

Always refer to existing implementations when creating new components to ensure you follow established patterns.
