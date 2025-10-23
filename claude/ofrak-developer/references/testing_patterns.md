# OFRAK Testing Patterns

This document covers patterns for writing comprehensive tests for OFRAK components and scripts.

## Testing Requirements

**OFRAK requires 100% test coverage at the statement or function level.**

This is enforced by CI. Pull requests that don't meet this requirement will not be merged.

## Test Data Strategy

**CRITICAL: Always use real binary data. Never create synthetic test data in code.**

### Test Asset Workflow

1. **Write tests assuming data exists** in `tests/components/assets/` directory
2. **Reference asset files by path** in your test code
3. **Instruct user to provide real data** at the specified path

### Example Pattern

```python
class TestMyFormatUnpacker:
    """Tests for MyFormatUnpacker."""

    @pytest.fixture
    def sample_file(self) -> bytes:
        """Load real sample file for testing."""
        # Reference asset file that user must provide
        asset_path = "tests/components/assets/sample.myformat"
        with open(asset_path, "rb") as f:
            return f.read()

    async def test_unpacks_real_file(
        self, ofrak_context: OFRAKContext, sample_file: bytes
    ):
        """Test unpacker with real MyFormat file."""
        resource = await ofrak_context.create_root_resource("sample.myformat", sample_file)
        resource.add_tag(MyFormat)

        await resource.run(MyFormatUnpacker)

        children = await resource.get_children()
        assert len(children) > 0
```

### User Instructions

When creating tests, instruct the user:

```
Please place a real MyFormat test file at:
  tests/components/assets/sample.myformat

IMPORTANT: Test data must be suitable for public distribution, as the OFRAK
repository is open source and publicly accessible. Use test data that is:
- Created by you
- Public domain
- Permissively licensed (e.g., CC0, MIT, BSD)
- Otherwise freely redistributable

You can obtain appropriate test data by:
- Creating your own test file with [tool]
- Using public domain samples from [source]
- Generating test cases yourself
- Extracting from openly licensed firmware/archives
```

### What NOT to Do

❌ **Don't create synthetic data:**
```python
# BAD - Don't do this
test_data = b"MYFT" + b"\x00" * 100  # Fake data
```

❌ **Don't generate test files programmatically:**
```python
# BAD - Don't do this
def create_fake_myformat():
    return build_fake_structure()  # Generated data
```

✅ **Do use real files:**
```python
# GOOD - Do this
with open("tests/components/assets/real_sample.myformat", "rb") as f:
    real_data = f.read()
```

### When Synthetic Data is Acceptable

Minimal synthetic data is acceptable ONLY for:
- Testing error conditions with intentionally malformed inputs
- Unit testing specific parsing functions with small, well-defined inputs
- Testing edge cases where real data would be impractical (e.g., 2GB files)

Even in these cases, prefer real data when possible.

## Test Structure

### Basic Test Pattern

```python
import pytest
from ofrak import OFRAKContext
from ofrak.resource import Resource

from my_module import MyComponent, MyComponentConfig


class TestMyComponent:
    """Tests for MyComponent."""

    @pytest.fixture
    async def test_resource(self, ofrak_context: OFRAKContext) -> Resource:
        """
        Create a test resource for MyComponent tests.

        Args:
            ofrak_context: OFRAK context fixture

        Returns:
            Test resource
        """
        # Create test data
        test_data = b"test binary data"

        # Create resource
        resource = await ofrak_context.create_root_resource("test.bin", test_data)
        return resource

    async def test_my_component_basic(
        self, test_resource: Resource, ofrak_context: OFRAKContext
    ):
        """Test MyComponent with basic input."""
        # Run component
        await test_resource.run(MyComponent)

        # Verify results
        result = await test_resource.get_data()
        assert result == b"expected output"

    async def test_my_component_with_config(
        self, test_resource: Resource, ofrak_context: OFRAKContext
    ):
        """Test MyComponent with custom configuration."""
        config = MyComponentConfig(option1="value", option2=123)
        await test_resource.run(MyComponent, config)

        # Verify results
        result = await test_resource.get_data()
        assert result == b"expected output with config"
```

## Fixture Patterns

### Standard Fixtures

OFRAK provides standard fixtures:

```python
@pytest.fixture
async def ofrak_context() -> OFRAKContext:
    """Provides an OFRAK context for tests."""
    # Provided by OFRAK test framework
```

### Custom Fixtures for Test Data

**Always reference real asset files:**

```python
@pytest.fixture
def sample_elf_binary() -> bytes:
    """Load real ELF binary for testing.

    User must provide: tests/components/assets/sample.elf
    """
    asset_path = "tests/components/assets/sample.elf"
    with open(asset_path, "rb") as f:
        return f.read()

@pytest.fixture
async def elf_resource(
    ofrak_context: OFRAKContext, sample_elf_binary: bytes
) -> Resource:
    """Create ELF resource for testing."""
    resource = await ofrak_context.create_root_resource(
        "test.elf", sample_elf_binary
    )
    return resource
```

### Parameterized Fixtures

```python
@pytest.fixture(params=[
    ("input1.bin", b"expected1"),
    ("input2.bin", b"expected2"),
    ("input3.bin", b"expected3"),
])
def test_case(request) -> tuple[str, bytes]:
    """Parameterized test cases."""
    return request.param
```

## Testing Identifiers

```python
from ofrak.core.magic import MagicMimeIdentifier, MagicDescriptionIdentifier


class TestMyFormatIdentifier:
    """Tests for MyFormatIdentifier."""

    @pytest.fixture
    def valid_myformat_file(self) -> bytes:
        """Load real valid MyFormat file.

        User must provide: tests/components/assets/valid.myf
        """
        with open("tests/components/assets/valid.myf", "rb") as f:
            return f.read()

    @pytest.fixture
    def invalid_format_file(self) -> bytes:
        """Load real non-MyFormat file.

        User must provide: tests/components/assets/not_myformat.bin
        """
        with open("tests/components/assets/not_myformat.bin", "rb") as f:
            return f.read()

    async def test_identifies_valid_format(
        self, ofrak_context: OFRAKContext, valid_myformat_file: bytes
    ):
        """Test that valid MyFormat files are identified."""
        resource = await ofrak_context.create_root_resource("test.myf", valid_myformat_file)

        # Run identifier
        await resource.run(MyFormatIdentifier)

        # Verify tag was added
        assert resource.has_tag(MyFormat)

    async def test_does_not_identify_invalid_format(
        self, ofrak_context: OFRAKContext, invalid_format_file: bytes
    ):
        """Test that non-MyFormat files are not identified."""
        resource = await ofrak_context.create_root_resource("test.bin", invalid_format_file)
        await resource.run(MyFormatIdentifier)

        # Verify tag was not added
        assert not resource.has_tag(MyFormat)

    async def test_identifies_with_magic(
        self, ofrak_context: OFRAKContext, valid_myformat_file: bytes
    ):
        """Test identification after magic identifiers run."""
        resource = await ofrak_context.create_root_resource("test.myf", valid_myformat_file)

        # Run magic identifiers first (simulating real workflow)
        await resource.run(MagicMimeIdentifier)
        await resource.run(MagicDescriptionIdentifier)
        await resource.run(MyFormatIdentifier)

        assert resource.has_tag(MyFormat)
```

## Testing Analyzers

```python
class TestMyFormatAnalyzer:
    """Tests for MyFormatAnalyzer."""

    @pytest.fixture
    def myformat_sample(self) -> bytes:
        """Load real MyFormat file for testing.

        User must provide: tests/components/assets/sample_v2.myf
        (A MyFormat file with version=2, compression=GZIP, entry_count=5)
        """
        with open("tests/components/assets/sample_v2.myf", "rb") as f:
            return f.read()

    @pytest.fixture
    async def myformat_resource(
        self, ofrak_context: OFRAKContext, myformat_sample: bytes
    ) -> Resource:
        """Create MyFormat test resource from real data."""
        resource = await ofrak_context.create_root_resource("test.myf", myformat_sample)
        resource.add_tag(MyFormat)
        return resource

    async def test_analyzes_format(self, myformat_resource: Resource):
        """Test MyFormatAnalyzer extracts correct attributes."""
        # Run analyzer
        await myformat_resource.run(MyFormatAnalyzer)

        # Get attributes
        attrs = await myformat_resource.analyze(MyFormatAttributes)

        # Verify
        assert attrs.version == 2
        assert attrs.compression_type == "GZIP"
        assert attrs.entry_count == 5

    async def test_analyzes_different_versions(self, ofrak_context: OFRAKContext):
        """Test analyzer handles different format versions.

        User must provide: tests/components/assets/sample_v1.myf
        (A MyFormat file with version=1, compression=NONE)
        """
        with open("tests/components/assets/sample_v1.myf", "rb") as f:
            data_v1 = f.read()

        resource = await ofrak_context.create_root_resource("test.myf", data_v1)
        resource.add_tag(MyFormat)

        await resource.run(MyFormatAnalyzer)
        attrs = await resource.analyze(MyFormatAttributes)

        assert attrs.version == 1
        assert attrs.compression_type == "NONE"
```

## Testing Unpackers

```python
class TestMyFormatUnpacker:
    """Tests for MyFormatUnpacker."""

    @pytest.fixture
    def archive_sample(self) -> bytes:
        """Load real MyFormat archive for testing.

        User must provide: tests/components/assets/archive_2files.myf
        (A MyFormat archive containing file1.txt and file2.txt)
        """
        with open("tests/components/assets/archive_2files.myf", "rb") as f:
            return f.read()

    @pytest.fixture
    async def archive_resource(
        self, ofrak_context: OFRAKContext, archive_sample: bytes
    ) -> Resource:
        """Create MyFormat archive resource from real data."""
        resource = await ofrak_context.create_root_resource("archive.myf", archive_sample)
        resource.add_tag(MyFormat)
        return resource

    async def test_unpacks_files(self, archive_resource: Resource):
        """Test unpacker extracts all files correctly."""
        # Run analyzer first (unpacker depends on it)
        await archive_resource.run(MyFormatAnalyzer)

        # Run unpacker
        await archive_resource.run(MyFormatUnpacker)

        # Get children
        from ofrak.core.filesystem import File
        children = await archive_resource.get_children_as_view(File)

        # Verify
        assert len(children) == 2

        file1 = [f for f in children if f.name == "file1.txt"][0]
        file2 = [f for f in children if f.name == "file2.txt"][0]

        file1_data = await file1.resource.get_data()
        file2_data = await file2.resource.get_data()

        assert file1_data == b"Hello, World!"
        assert file2_data == b"Goodbye!"

    async def test_unpacks_empty_archive(self, ofrak_context: OFRAKContext):
        """Test unpacker handles empty archives.

        User must provide: tests/components/assets/archive_empty.myf
        (An empty MyFormat archive with 0 entries)
        """
        with open("tests/components/assets/archive_empty.myf", "rb") as f:
            empty_archive = f.read()

        resource = await ofrak_context.create_root_resource("empty.myf", empty_archive)
        resource.add_tag(MyFormat)

        await resource.run(MyFormatAnalyzer)
        await resource.run(MyFormatUnpacker)

        children = await resource.get_children()
        assert len(children) == 0
```

## Testing Modifiers

```python
class TestMyModifier:
    """Tests for MyModifier."""

    @pytest.fixture
    def test_binary(self) -> bytes:
        """Load real binary for modification testing.

        User must provide: tests/components/assets/test_binary.bin
        (Binary file containing the target strings to replace)
        """
        with open("tests/components/assets/test_binary.bin", "rb") as f:
            return f.read()

    async def test_replaces_string(
        self, ofrak_context: OFRAKContext, test_binary: bytes
    ):
        """Test modifier replaces target string in real binary."""
        resource = await ofrak_context.create_root_resource("test.bin", test_binary)

        # Run modifier
        config = MyModifierConfig(
            target_string=b"Hello",
            replacement=b"Goodbye"
        )
        await resource.run(MyModifier, config)

        # Verify replacement occurred
        modified_data = await resource.get_data()
        assert b"Goodbye" in modified_data
        assert b"Hello" not in modified_data

    async def test_no_match_no_change(
        self, ofrak_context: OFRAKContext, test_binary: bytes
    ):
        """Test modifier leaves data unchanged when no match."""
        resource = await ofrak_context.create_root_resource("test.bin", test_binary)

        config = MyModifierConfig(
            target_string=b"NotFound",
            replacement=b"Something"
        )
        await resource.run(MyModifier, config)

        modified_data = await resource.get_data()
        assert modified_data == test_binary
```

## Testing Packers

```python
class TestMyFormatPacker:
    """Tests for MyFormatPacker."""

    async def test_packs_files(self, ofrak_context: OFRAKContext):
        """Test packer creates valid archive from files."""
        from ofrak.core.filesystem import File

        # Create root resource
        resource = await ofrak_context.create_root_resource("archive.myf", b"")
        resource.add_tag(MyFormat)

        # Add child files
        await resource.create_child(
            tags=(File,),
            data=b"File 1 content",
            attributes=(File("file1.txt", 14),)
        )
        await resource.create_child(
            tags=(File,),
            data=b"File 2 content",
            attributes=(File("file2.txt", 14),)
        )

        # Run packer
        await resource.run(MyFormatPacker)

        # Verify packed data
        packed_data = await resource.get_data()

        # Check magic
        assert packed_data[:4] == b"MYFT"

        # Verify can be unpacked
        await resource.run(MyFormatUnpacker)
        children = await resource.get_children_as_view(File)
        assert len(children) == 2
```

## Testing External Tool Components

**CRITICAL: Do NOT mock external tools. Test with real tools installed.**

```python
class TestExternalToolComponent:
    """Tests for components using external tools."""

    async def test_with_external_tool(self, ofrak_context: OFRAKContext):
        """Test component that uses external tool."""
        # Create test resource with appropriate binary data
        resource = await ofrak_context.create_root_resource("test.bin", b"real test data")

        # Run component with real external tool
        await resource.run(MyExternalToolComponent)

        # Verify component processed real tool output correctly
        result = await resource.get_data()
        assert result == b"expected real output"

    async def test_handles_tool_failure(self, ofrak_context: OFRAKContext):
        """Test component handles external tool failures."""
        # Create resource with data that will cause tool to fail
        invalid_data = b"corrupted or invalid data"
        resource = await ofrak_context.create_root_resource("test.bin", invalid_data)

        # Verify component raises appropriate error when tool fails
        with pytest.raises(ComponentError):
            await resource.run(MyExternalToolComponent)
```

**Requirements for external tool testing:**
- External tools must be installed in test environment
- Use real binary test data that exercises the tool
- Test both success and failure cases with real tool behavior
- Document required external dependencies in test docstrings

## Testing Resource Views

```python
class TestMyFormatView:
    """Tests for MyFormat resource view."""

    @pytest.fixture
    async def myformat_view(self, ofrak_context: OFRAKContext) -> MyFormat:
        """Create MyFormat view for testing."""
        data = create_test_myformat_data()
        resource = await ofrak_context.create_root_resource("test.myf", data)
        resource.add_tag(MyFormat)
        return await resource.view_as(MyFormat)

    async def test_get_version(self, myformat_view: MyFormat):
        """Test getting format version."""
        version = await myformat_view.get_version()
        assert version == 1

    async def test_extract_entry(self, myformat_view: MyFormat):
        """Test extracting specific entry."""
        entry_data = await myformat_view.extract_entry(0)
        assert entry_data == b"expected entry data"
```

## Parameterized Tests

**Use real test files for parameterized testing:**

```python
@pytest.mark.parametrize("input_file,expected_file", [
    ("tests/components/assets/sample1.bin", "tests/components/assets/expected1.bin"),
    ("tests/components/assets/sample2.bin", "tests/components/assets/expected2.bin"),
    ("tests/components/assets/sample3.bin", "tests/components/assets/expected3.bin"),
])
async def test_multiple_cases(
    ofrak_context: OFRAKContext, input_file: str, expected_file: str
):
    """Test component with multiple real file pairs.

    User must provide:
    - tests/components/assets/sample1.bin and expected1.bin
    - tests/components/assets/sample2.bin and expected2.bin
    - tests/components/assets/sample3.bin and expected3.bin
    """
    with open(input_file, "rb") as f:
        test_input = f.read()
    with open(expected_file, "rb") as f:
        expected = f.read()

    resource = await ofrak_context.create_root_resource("test.bin", test_input)
    await resource.run(MyComponent)

    result = await resource.get_data()
    assert result == expected
```

## Error Handling Tests

**Prefer real malformed files, but minimal synthetic data is acceptable for error testing:**

```python
async def test_invalid_format_raises_error(self, ofrak_context: OFRAKContext):
    """Test component raises appropriate error for invalid input.

    Option 1 (preferred): Use real corrupted file
    User provides: tests/components/assets/corrupted.myf

    Option 2 (acceptable): Minimal synthetic malformed data
    """
    # Preferred: Load real corrupted file
    # with open("tests/components/assets/corrupted.myf", "rb") as f:
    #     invalid_data = f.read()

    # Acceptable for error testing: minimal synthetic invalid data
    invalid_data = b"INVALID"

    resource = await ofrak_context.create_root_resource("test.bin", invalid_data)

    with pytest.raises(ValueError, match="Invalid format"):
        await resource.run(MyComponent)

async def test_missing_dependency_raises_error(
    self, ofrak_context: OFRAKContext, test_binary: bytes
):
    """Test component raises error when dependency missing."""
    resource = await ofrak_context.create_root_resource("test.bin", test_binary)

    # Don't run required analyzer
    with pytest.raises(ComponentDependencyError):
        await resource.run(MyComponent)
```

## Integration Tests

```python
async def test_full_workflow(self, ofrak_context: OFRAKContext):
    """Test complete workflow with multiple components.

    User must provide: tests/components/assets/test_workflow.myf
    (A complete MyFormat file for end-to-end testing)
    """
    # Load real test file
    with open("tests/components/assets/test_workflow.myf", "rb") as f:
        test_data = f.read()

    resource = await ofrak_context.create_root_resource("test.myf", test_data)

    # Identify
    await resource.run(MyFormatIdentifier)
    assert resource.has_tag(MyFormat)

    # Analyze
    await resource.run(MyFormatAnalyzer)
    attrs = await resource.analyze(MyFormatAttributes)
    assert attrs.version == 1

    # Unpack
    await resource.unpack()
    children = await resource.get_children()
    assert len(children) > 0

    # Modify
    config = MyModifierConfig(target_string=b"old", replacement=b"new")
    await resource.run(MyModifier, config)

    # Pack
    await resource.pack()

    # Save
    await resource.flush_data_to_disk("modified.myf")
```

## Test Organization

### File Structure

```
tests/
├── __init__.py
├── test_my_identifier.py      # Identifier tests
├── test_my_analyzer.py         # Analyzer tests
├── test_my_unpacker.py         # Unpacker tests
├── test_my_modifier.py         # Modifier tests
├── test_my_packer.py           # Packer tests
├── test_my_view.py             # Resource view tests
└── data/                       # Test data
    ├── sample1.myf
    ├── sample2.myf
    └── ...
```

### Test Class Organization

```python
class TestMyComponent:
    """Tests for MyComponent.

    Organized by feature/scenario:
    - Basic functionality
    - Edge cases
    - Error handling
    - Integration with other components
    """

    # Fixtures
    @pytest.fixture
    def setup(self):
        ...

    # Basic functionality tests
    async def test_basic_case(self):
        ...

    # Edge case tests
    async def test_empty_input(self):
        ...

    async def test_large_input(self):
        ...

    # Error handling tests
    async def test_invalid_input_raises_error(self):
        ...

    # Integration tests
    async def test_works_with_other_component(self):
        ...
```

## Coverage Best Practices

1. **Test all code paths**: Ensure every branch is tested
2. **Test error conditions**: Don't just test happy paths
3. **Test edge cases**: Empty inputs, maximum sizes, boundary conditions
4. **Test integrations**: How components work together
5. **Use parameterized tests**: Cover multiple scenarios efficiently
6. **Use real data and tools**: Test with actual binaries and real external tools (no mocking)
7. **Keep tests isolated**: Each test should be independent
8. **Name tests clearly**: Test names should describe what they test
9. **Use appropriate assertions**: Be specific about what you're checking
10. **Document complex tests**: Add comments explaining non-obvious test logic

## Running Tests

```bash
# Run all tests
pytest

# Run specific test file
pytest tests/test_my_component.py

# Run specific test
pytest tests/test_my_component.py::TestMyComponent::test_basic_case

# Run with coverage
pytest --cov=my_module tests/

# Generate coverage report
pytest --cov=my_module --cov-report=html tests/
```

## CI/CD Integration

Tests are automatically run by GitHub Actions on every PR. Ensure:
- All tests pass locally before pushing
- Coverage meets 100% requirement
- Tests are reasonably fast (optimize test data size, not by mocking)
- Tests are deterministic (no random failures)
- Required external tools are available in CI environment

## Additional Resources

- pytest documentation: https://docs.pytest.org/
- OFRAK testing examples: Look at existing tests in `ofrak/tests/` directory
- Coverage documentation: https://coverage.readthedocs.io/
