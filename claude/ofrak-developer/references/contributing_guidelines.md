# OFRAK Contributing Guidelines

This document contains the key contributing guidelines extracted from the OFRAK repository.

## Pull Request Best Practices

### Keep PRs Focused
- Each PR should focus on ONE change
- Avoid large changes that affect functionality in multiple ways
- Break up large changes into multiple pull requests
- This makes PRs easier to review and reduces the chance of merge conflicts

### Review Size Guidelines
When reviewing, it can take developers a little over an hour to get through a few hundred lines of code and find most defects. Keep your contributions to a reasonable review size.

## Changelog Requirements

The following OFRAK packages maintain changelogs and MUST be updated if changes affect them:

- `ofrak_core` → `ofrak_core/CHANGELOG.md`
- `ofrak_io` → `ofrak_io/CHANGELOG.md`
- `ofrak_patch_maker` → `ofrak_patch_maker/CHANGELOG.md`
- `ofrak_type` → `ofrak_type/CHANGELOG.md`
- `ofrak_tutorial` → `ofrak_tutorial/CHANGELOG.md`
- `ofrak_angr` → `disassemblers/ofrak_angr/CHANGELOG.md`
- `ofrak_capstone` → `disassemblers/ofrak_capstone/CHANGELOG.md`
- `ofrak_ghidra` → `disassemblers/ofrak_ghidra/CHANGELOG.md`
- `ofrak_pyghidra` → `disassemblers/ofrak_pyghidra/CHANGELOG.md`
- `ofrak_cached_disassembly` → `disassemblers/ofrak_cached_disassembly/CHANGELOG.md`

### Changelog Format

Changelogs follow the [Keep a Changelog](https://keepachangelog.com/en/1.0.0/) format and adhere to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

Each changelog has sections:
- **Added** - for new features
- **Fixed** - for bug fixes
- **Changed** - for changes in existing functionality
- **Deprecated** - for soon-to-be removed features
- **Removed** - for now removed features
- **Security** - for security-related changes

### Changelog Entry Format

Add your changes to the `Unreleased` section. The format is:

```markdown
- Brief description of the change ([#PR_NUMBER](https://github.com/redballoonsecurity/ofrak/pull/PR_NUMBER))
```

**Since the PR hasn't been created yet, use a placeholder:**
```markdown
- Brief description of the change ([#PLACEHOLDER](https://github.com/redballoonsecurity/ofrak/pull/PLACEHOLDER))
```

**Ask the user to update the placeholder with the actual PR number once the PR is published.**

### Example Changelog Entries

Good examples from existing changelogs:

```markdown
### Added
- Add `-V, --version` flag to ofrak cli ([#652](https://github.com/redballoonsecurity/ofrak/pull/652))
- Add modifier to add and remove sections using lief. ([#443](https://github.com/redballoonsecurity/ofrak/pull/443))
- Add UEFI binary unpacker. ([#399](https://github.com/redballoonsecurity/ofrak/pull/399))

### Fixed
- Fix `java` and `apktool` CLI arguments for checking components. ([#390](https://github.com/redballoonsecurity/ofrak/pull/390))
- Fixed front end "Replace" button. Before it was appending new data instead of replacing it as intended. ([#403](https://github.com/redballoonsecurity/ofrak/pull/403))
- Fix bug in OFRAK GUI server which causes an error when parsing a default config value of bytes. ([#409](https://github.com/redballoonsecurity/ofrak/pull/409))

### Changed
- By default, the ofrak log is now `ofrak-YYYYMMDDhhmmss.log` rather than just `ofrak.log` and the name can be specified on the command line ([#480](https://github.com/redballoonsecurity/ofrak/pull/480))
- `Resource.flush_to_disk` method renamed to `Resource.flush_data_to_disk`. ([#373](https://github.com/redballoonsecurity/ofrak/pull/373))
```

## Testing Requirements

**The packages in this repository maintain 100% test coverage, either at the statement or function level.**

This test coverage is enforced in the CI pipeline. Pull Requests that do not meet this requirement will not be merged.

When contributing:
1. Always create tests for your changes
2. Ensure your tests cover all new code paths
3. Run tests locally before submitting PR
4. Tests should be placed in the appropriate `tests/` directory for the module

## Pre-commit Hooks

Please install and run the `pre-commit` hooks before submitting your PR. This helps maintain code quality and consistency.

## Code Review Guidelines

1. Please be respectful. Remember to discuss the merits of the idea, not the individual.
2. Please back your code review suggestions with technical reasoning.
3. If the value of your code review suggestion is subjective, please use words like "I think...".
4. If you have to write a long-winded explanation in the review, we expect to see some code comments.
5. Please keep your contributions within the scope of the proposed fix, feature, or maintenance task.

## Python Coding Standard

Please see `ofrak/docs/contributor-guide/getting-started.md` in the OFRAK repository for functional and stylistic expectations.

## Linking to Issues

Please link your Pull Request to an outstanding issue if one exists. For small fixes in docs or typos, you probably won't need to create an issue first.

For feature proposals or very large fixes, create an issue first to discuss it beforehand.

## Dependency Management

**OFRAK uses a multi-package structure where each package manages its own dependencies.**

### Package Structure

Each OFRAK package has its own:
- `requirements.txt` - Python dependencies
- `Dockerstub` - System/apt dependencies
- `CHANGELOG.md` - Version history

When adding dependencies to a specific OFRAK package, you MUST update that package's dependency files, not a global one.

### Adding Python Dependencies

**When adding a Python module dependency:**

1. **Check PyPI for the latest stable version**
   - Visit https://pypi.org/project/package-name/
   - Identify the latest stable release version
   - Verify it's not a pre-release (alpha, beta, rc)

2. **Pin to the exact latest version**
   - Use `==` notation with the specific version
   - Example: `package-name==2.5.3` (not `>=` or `~=`)

3. **Update the package's `requirements.txt` file**
   - Locate: `ofrak_core/requirements.txt`, `ofrak_patch_maker/requirements.txt`, etc.
   - Add the pinned dependency

4. **Update the package's `CHANGELOG.md`**
   - Note the new dependency under "Added" or "Changed" section

**Example:**
```
# ofrak_core/requirements.txt
existing-package==1.2.3
new-package==2.5.3  # Latest stable version as of 2024-01-15
```

### Adding System Dependencies

**When adding apt/system dependencies:**

1. Locate the appropriate package's `Dockerstub` file
   - Example: `ofrak_core/Dockerstub`, `disassemblers/ofrak_ghidra/Dockerstub`
2. Add the apt package(s)
3. Update the package's `CHANGELOG.md` noting the new dependency

**Example Dockerstub:**
```dockerfile
# ofrak_core/Dockerstub
RUN apt-get update && \
    apt-get install -y --no-install-recommends \
        existing-tool \
        new-tool && \  # New dependency added
    rm -rf /var/lib/apt/lists/*
```

### Dependency Guidelines

**IMPORTANT RULES:**

1. ✅ **Always check PyPI for latest stable version before pinning**
2. ✅ **Pin Python dependencies to exact version (use `==`)**
3. ✅ **Use packages from PyPI or standard apt repositories**
4. ✅ **Prefer well-maintained, cross-platform dependencies**
5. ❌ **AVOID dependencies that must be built from source**
6. ❌ **AVOID platform-specific dependencies without alternatives**
7. ❌ **AVOID dependencies with complex manual installation**

### Common Package Locations

- **Core components**: `ofrak_core/requirements.txt` and `ofrak_core/Dockerstub`
- **Patch maker**: `ofrak_patch_maker/requirements.txt` and `ofrak_patch_maker/Dockerstub`
- **Type definitions**: `ofrak_type/requirements.txt` and `ofrak_type/Dockerstub`
- **Disassemblers**: `disassemblers/ofrak_*/requirements.txt` and `disassemblers/ofrak_*/Dockerstub`
- **I/O operations**: `ofrak_io/requirements.txt` and `ofrak_io/Dockerstub`

### Verifying Dependencies

Before submitting PR:

1. Test that dependencies install correctly
2. Verify Docker build succeeds with new dependencies
3. Document any special installation requirements in component docstring
4. Update CHANGELOG.md with dependency changes

## Maintainers

Every Pull Request requires at least one review by an OFRAK maintainer. You may request review from specific maintainers in your PR, or a maintainer will pick up your PR for review.
