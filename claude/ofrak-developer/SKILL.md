---
name: ofrak-developer
description: Guide for OFRAK contributors and developers. Use this skill when writing OFRAK scripts, creating/modifying OFRAK components, adding tests, fixing bugs, or contributing to OFRAK internals. Ensures contributions follow OFRAK standards, automatically creates comprehensive tests, and maintains 100% code coverage. Superset of ofrak-user skill.
---

# OFRAK Developer

## Overview

Comprehensive guide for contributing to the OFRAK (Open Firmware Reverse Analysis Konsole) project and writing OFRAK scripts. This skill covers both using OFRAK (writing standalone scripts) and developing OFRAK (contributing components, fixing bugs, refactoring internals). Ensures all contributions follow OFRAK's coding standards, include comprehensive tests, and meet the 100% code coverage requirement.

**This skill is stateless** - it recognizes existing code without tests and creates appropriate tests. It handles script writing, component development, bugfixes, refactoring, and ensures compliance with contribution guidelines.

## When to Use This Skill

Invoke this skill when:
- **Writing OFRAK Scripts** - Creating or modifying standalone Python scripts that use OFRAK
- **Adding Components** - Creating new analyzers, unpackers, modifiers, packers, or identifiers
- **Modifying Components** - Fixing bugs, refactoring, or enhancing existing OFRAK components
- **Writing Tests** - Creating tests for components that lack them (stateless - detects missing tests)
- **Contributing to OFRAK** - Making any changes to OFRAK internals, GUI, or modules
- **Creating Pull Requests** - Preparing contributions that meet OFRAK standards

## Core Principles

### 1. Stateless Test Creation

**CRITICAL: Automatically detect and create missing tests.**

When working on any OFRAK code:
1. Check if tests exist for the component/function
2. If tests are missing, create comprehensive tests automatically
3. Ensure 100% coverage (statement or function level)
4. Follow testing patterns from `references/testing_patterns.md`

**Do NOT ask user if they want tests - always create them automatically.**

### 2. Mandatory Documentation Reading

**BEFORE implementing any component, MUST read relevant guides:**

- **Always read**: `ofrak/docs/contributor-guide/getting-started.md`
- **For components**: Read component-specific guide from `ofrak/docs/contributor-guide/component/`
  - Unpacker → `unpacker.md`
  - Analyzer → `analyzer.md`
  - Modifier → `modifier.md`
  - Packer → `packer.md`
  - Identifier → `identifier.md`

### 3. Follow OFRAK Patterns

**Research similar implementations before writing code:**

1. Search for similar components in the codebase
2. Read similar component implementations
3. Follow the same patterns and structure
4. Check `references/component_patterns.md` for templates

### 4. Focused Contributions

**Each PR should focus on ONE change:**

- Don't mix features, bugfixes, and refactoring
- Break large changes into multiple focused PRs
- Update appropriate CHANGELOG.md files
- Use `#PLACEHOLDER` for PR numbers in changelog

## Decision Tree: Which Component Type?

```
Do you need to IDENTIFY a file format?
  └─> Identifier (adds tags, no data extraction)

Do you need to EXTRACT INFORMATION (metadata, headers)?
  └─> Analyzer (returns attributes, no children)

Do you need to EXTRACT CONTENT (files, sections, embedded data)?
  └─> Unpacker (creates children, no modification)

Do you need to MODIFY DATA (patch, replace, inject)?
  └─> Modifier (changes data, no children)

Do you need to REBUILD from modified children?
  └─> Packer (reconstructs parent from children)
```

## Common Component Combinations

**New file format support:**
1. Identifier - detect the format
2. Analyzer - extract metadata
3. Unpacker - extract embedded content
4. Packer - rebuild after modifications (optional)

**Analysis only:**
1. Identifier - detect format
2. Analyzer - extract information
(No Unpacker/Modifier/Packer needed)

**Binary patching:**
1. Identifier - detect format (may already exist)
2. Modifier - apply patches

**Archive modification:**
1. Identifier - detect archive type
2. Unpacker - extract files
3. Modifier - modify extracted files
4. Packer - rebuild archive

## Contribution Workflow

### Step 0: Check for Existing Issues and PRs (Recommended)

**Best practice: Check for duplicate work before starting:**

To avoid duplicate effort, recommend the user check:
- Existing GitHub issues: https://github.com/redballoonsecurity/ofrak/issues
- Open pull requests: https://github.com/redballoonsecurity/ofrak/pulls

**Search tips**:
- Use relevant keywords (e.g., "ZIP unpacker", "ELF analyzer", "memory leak")
- Check both open and closed issues/PRs
- Review maintainer comments on similar requests

**If duplicate found**:
- For open issue: Comment on existing issue instead of creating new one
- For open PR: Consider collaborating on existing PR
- For closed issue/PR: Review why it was closed before proceeding

**Creating new issues**:
- Large features: Issue first for discussion (recommended)
- Bug fixes: Issue optional but helpful for tracking
- Small improvements: Can go directly to PR

### Step 1: Determine Task Type

Is this a:
- **Script writing task?** → Follow Script Writing Workflow below
- **Component development task?** → Follow Component Development Workflow below
- **Bug fix task?** → Follow Bug Fix Workflow below
- **Refactoring task?** → Follow Refactoring Workflow below

### Step 2A: Script Writing Workflow

For writing standalone OFRAK scripts:

**Follow the detailed 7-step workflow in `references/ofrak_script_patterns.md`**

Key requirements:
- Main function: `async def main(ofrak_context: OFRAKContext, ...)`
- Use `ofrak.run(main, ...)` in `if __name__ == "__main__"`
- Include argparse for CLI arguments
- Only use components that actually exist (verify in `references/ofrak_usage_guide.md`)

### Step 2B: Component Development Workflow

For creating new OFRAK components:

**Follow the detailed 11-step workflow in `references/component_patterns.md` → "Component Development Workflow"**

Quick summary:
1. **Read documentation** (MANDATORY) - getting-started.md + component-specific guide
2. **Research similar components** - Search codebase for patterns
3. **Use component template** - Start from `assets/component_template.py.template`

4. **Analyze implementation approach** (if using external tools):

   **CRITICAL: Perform Python vs External Tool analysis**

   If component needs external tools, evaluate:

   **Use External Tool When:**
   - Tool is widely used and well-tested (e.g., `7z`, `squashfs-tools`)
   - Format is complex (filesystems, compression algorithms)
   - Tool is **cross-platform** (macOS/Linux/Windows)
   - Tool has stable API/output format
   - Performance is critical
   - Reimplementation would be error-prone

   **Use Pure Python When:**
   - Format is simple or good Python libraries exist
   - No suitable cross-platform external tool available
   - External tool would add heavy dependency
   - Need fine-grained control over parsing

   **Cross-Platform Requirements:**
   - External tools MUST work on macOS, Linux, AND Windows
   - Verify availability in package managers (brew, apt, chocolatey)
   - Document installation requirements
   - ❌ Avoid: Linux-only tools, kernel modules, platform-specific utilities

   See `references/component_patterns.md` for detailed analysis framework.

5. **Implement using Write/Test/Evaluate Loop** (CRITICAL):

   **Implementation → Test → Evaluate → Repeat until ✅**

   **A. Write Implementation:**
   - Follow structure from documentation and similar components
   - Use proper type annotations and comprehensive docstrings
   - Handle errors appropriately, match OFRAK coding style
   - **If adding dependencies**: See `references/contributing_guidelines.md` → "Dependency Management"
     - Python modules → Pin to latest stable version in package's `requirements.txt`
     - Apt packages → Add to package's `Dockerstub`
     - Avoid dependencies requiring build from source

   **B. Create Tests Automatically:**
   - Use `assets/test_template.py.template` as starting point
   - Follow `references/testing_patterns.md` patterns
   - Cover all code paths, edge cases, and error conditions
   - **NEVER MOCK** - test with real code, real tools, real binary data
   - **Test Data Strategy**:
     - Write tests assuming real data exists in `tests/components/assets/`
     - Reference asset files by path (e.g., `tests/components/assets/sample.dmg`)
     - Instruct user to place real test files: "Place test file at `tests/components/assets/sample.dmg`"
     - **Remind user**: Test data must be suitable for public distribution (self-created, public domain, or permissively licensed)
     - ❌ Don't create synthetic data in test code
     - ❌ Don't generate test files programmatically

   **C. Run and Evaluate:**
   - Execute: `pytest path/to/test_file.py -v --cov=module_name`
   - Check: ✅ All tests pass? ✅ 100% coverage? ✅ Edge cases covered?
   - If NO → Fix code/tests → Re-run → Repeat until all ✅

   **⚠️ USER MUST VERIFY:**
   - LLM-generated code for bugs and quality standards
   - Tests actually test functionality (not just coverage cheating)
   - Real data usage where applicable

   **Do NOT proceed until: tests pass + 100% coverage + user verification.*

6. **Update changelog**:
   - Locate the appropriate CHANGELOG.md file for the modified package
   - Most components go in `ofrak_core/CHANGELOG.md`
   - Add entry with `#PLACEHOLDER` for PR number
   - Follow format in `references/contributing_guidelines.md`

### Step 2C: Bug Fix Workflow

For fixing bugs in existing code:

1. **Understand the bug** - Read error messages, stack traces
2. **Locate affected code** - Find the buggy component/function
3. **Check if tests exist**:
   - If tests exist: Fix code and update tests
   - If no tests: **Create tests first** (test-driven fix)
4. **Fix the bug** - Make minimal focused changes
5. **Verify fix** - Run tests to ensure bug is fixed
6. **Update changelog** - Add entry under "Fixed" section

### Step 2D: Refactoring Workflow

For refactoring existing code:

1. **Check existing tests**:
   - If tests missing: **Create tests first**
   - Tests act as safety net for refactoring
2. **Plan refactoring** - What needs to change?
3. **Refactor incrementally** - Small steps, run tests after each
4. **Ensure tests still pass** - Verify behavior unchanged
5. **Update changelog** - Add entry under "Changed" section

## Component Types and Patterns

### Identifier Pattern

```python
class MyFormatIdentifier(Identifier):
    """Identify MyFormat files by checking signature."""

    id = b"MyFormatIdentifier"
    targets = ()

    async def identify(self, resource: Resource, config=None) -> None:
        data = await resource.get_data()
        if data[:4] == b"MYFT":
            resource.add_tag(MyFormat)
```

### Analyzer Pattern

```python
class MyFormatAnalyzer(Analyzer[None, MyFormatAttributes]):
    """Extract metadata from MyFormat files."""

    id = b"MyFormatAnalyzer"
    targets = (MyFormat,)
    outputs = (MyFormatAttributes,)

    async def analyze(self, resource: Resource, config=None) -> MyFormatAttributes:
        data = await resource.get_data()
        # Extract and return attributes
        return MyFormatAttributes(...)
```

### Unpacker Pattern

```python
class MyFormatUnpacker(Unpacker[None]):
    """Unpack MyFormat archives."""

    id = b"MyFormatUnpacker"
    targets = (MyFormat,)
    children = (File,)

    async def unpack(self, resource: Resource, config=None) -> None:
        data = await resource.get_data()
        # Extract entries and create children
        await resource.create_child(tags=(File,), data=entry_data, ...)
```

### Modifier Pattern

```python
class MyModifier(Modifier[MyModifierConfig]):
    """Modify MyFormat resources."""

    id = b"MyModifier"
    targets = (MyFormat,)

    async def modify(self, resource: Resource, config: MyModifierConfig) -> None:
        data = await resource.get_data()
        modified = transform(data, config)
        resource.queue_patch(Range(0, len(data)), modified)
```

### Packer Pattern

```python
class MyFormatPacker(Packer[None]):
    """Pack MyFormat archives."""

    id = b"MyFormatPacker"
    targets = (MyFormat,)

    async def pack(self, resource: Resource, config=None) -> None:
        children = await resource.get_children()
        packed_data = build_archive(children)
        resource.queue_patch(Range(0, original_size), packed_data)
```

## Changelog Management

**Every change requires a changelog entry.**

1. **Find correct changelog**:
   - Locate the appropriate CHANGELOG.md file for the modified package
   - Common locations:
     - `ofrak_core/CHANGELOG.md` - Core components, formats, binary analysis
     - `ofrak_patch_maker/CHANGELOG.md` - Patch maker modifications
     - `disassemblers/ofrak_*/CHANGELOG.md` - Disassembler-specific changes
   - If unsure, look for CHANGELOG.md in the same package as the modified file

2. **Add entry format**:
   ```markdown
   ### [Added/Fixed/Changed/etc]
   - Brief description ([#PLACEHOLDER](https://github.com/redballoonsecurity/ofrak/pull/PLACEHOLDER))
   ```

3. **Remind user**:
   "Please update #PLACEHOLDER with actual PR number after creating PR"

## Pull Request Preparation

1. **Quality checklist**: Code follows patterns, tests pass (100% coverage), changelog updated with PLACEHOLDER, example provided
2. **PR description**: Read `ofrak/.github/pull_request_template.md`, fill all sections concisely (5-7 sentences max)
3. **Output**: Filled PR template to console for copy/paste
4. **Post-PR**: Update #PLACEHOLDER with actual PR number, link to related issues

**Important**: Don't hardcode template format (read from file), don't add "Generated with Claude Code" attributions

## Important Reminders

### Always DO:
- ✅ **READ relevant contributor guides FIRST** (getting-started.md + component-specific)
- ✅ **RESEARCH similar components** before implementing
- ✅ **CREATE TESTS AUTOMATICALLY** - never skip, never ask
- ✅ **ENSURE 100% test coverage** (required by CI)
- ✅ **TEST WITH REAL DATA** - prefer actual binary samples over synthetic/mock data
- ✅ Follow OFRAK coding patterns and style
- ✅ Use proper type annotations throughout
- ✅ Include comprehensive docstrings
- ✅ Keep PRs focused on one change
- ✅ Update correct CHANGELOG.md file
- ✅ Create example usage script (output to console)
- ✅ Read actual PR template from ofrak/.github/pull_request_template.md (don't hardcode)
- ✅ Keep PR descriptions concise (5-7 sentences max)
- ✅ Use proper async/await patterns
- ✅ Handle errors gracefully

### Never DO:
- ❌ Skip reading contributor documentation
- ❌ Ask user if they want tests - always create them
- ❌ Submit code without tests
- ❌ Miss coverage requirements (100% required)
- ❌ Create tests that cheat coverage without actually testing functionality
- ❌ Mix multiple unrelated changes in one PR
- ❌ Forget to update changelog
- ❌ Hardcode PR template format (always read from file)
- ❌ Make PR descriptions overly verbose
- ❌ Add "Generated with Claude Code" attributions by default
- ❌ Invent component names without verifying they exist
- ❌ Use synchronous patterns with OFRAK (must be async)
- ❌ Create documentation files unless explicitly requested

### ⚠️ CRITICAL: User Must Verify LLM-Generated Code
**The user MUST manually review all LLM-generated contributions:**
- 🔍 **Check for bugs and errors** - LLMs can make mistakes
- 🔍 **Verify OFRAK code quality** - Ensure standards are maintained
- 🔍 **Validate tests** - Tests must actually test, not just achieve coverage
- 🔍 **Prefer real data** - Use actual binary samples when available, not just synthetic test data
- 🔍 **Review logic** - Ensure implementations are correct, not just plausible

**AI-generated code is a starting point, not a finished product. User review is essential.**

## Script Writing (Subset: OFRAK User)

This skill includes all ofrak-user functionality. For script-only tasks:

- Check `references/ofrak_script_patterns.md` for patterns
- Check `references/ofrak_usage_guide.md` for available components
- Use `assets/script_template.py.template` as starting point
- Follow proper async/await structure
- Only use verified, existing components

See ofrak-user skill or references for comprehensive script writing guidance.

## Additional Resources

### Bundled References

**For script writing:**
- `references/ofrak_script_patterns.md` - OFRAK script patterns and **7-step workflow**
- `references/ofrak_usage_guide.md` - Available components guide

**For component development:**
- `references/component_patterns.md` - Component implementation patterns, detailed component type guide, and **11-step development workflow**
- `references/testing_patterns.md` - Comprehensive testing guide
- `references/contributing_guidelines.md` - Contribution standards

### Bundled Assets

- `assets/script_template.py.template` - OFRAK script template
- `assets/component_template.py.template` - Component implementation template
- `assets/test_template.py.template` - Test suite template

### External Resources (in OFRAK repository)

**Must read for contributions:**
- `ofrak/docs/contributor-guide/getting-started.md` - Coding standards, testing
- `ofrak/docs/contributor-guide/component/[type].md` - Component-specific guides

**For reference:**
- `ofrak/examples/` - Example OFRAK scripts
- `ofrak/.github/pull_request_template.md` - PR template

## Getting Help

- **OFRAK Documentation**: Available in the cloned `ofrak` repository under `ofrak/docs/`. If you don't have the repo cloned, instruct the user to clone it: `git clone https://github.com/redballoonsecurity/ofrak.git`
- **GitHub Issues**: https://github.com/redballoonsecurity/ofrak/issues
- **Slack Community**: https://join.slack.com/t/ofrak/shared_invite/zt-1jku9h6r5-mY7CeeZ4AT8JVmu5YWw2Qg
