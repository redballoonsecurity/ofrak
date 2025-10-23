# OFRAK Developer Skill for Claude Code

A Claude Code skill for OFRAK contributors and developers. This skill provides guidance for writing OFRAK scripts, creating/modifying OFRAK components, adding tests, fixing bugs, and contributing to OFRAK internals while maintaining 100% code coverage.

## Overview

This skill enables Claude Code to:
- Write OFRAK scripts and components following best practices
- Create comprehensive tests with 100% code coverage
- Develop and modify OFRAK internals
- Debug and fix OFRAK-related issues
- Follow OFRAK coding standards and conventions

## Prerequisites

- Claude Code

## Installation

### Quick Install

```bash
# Install the skill
make install
```

This will create a symlink from `~/.claude/skills/ofrak-developer` to the skill directory.

### Manual Installation

If you prefer to install manually:

```bash
mkdir -p ~/.claude/skills
ln -sf $(pwd)/ofrak-developer ~/.claude/skills/ofrak-developer
```

### Packaging

```bash
make package
```
This will create `ofrak-developer.zip`, which can be installed in the Claude Code desktop app.

## Usage

Once installed, the skill is automatically available in Claude Code when working on OFRAK-related projects.

### Activating the Skill

The skill activates automatically when you ask Claude Code to work on OFRAK development tasks, such as creating components, adding tests, or modifying OFRAK internals.

### Common Use Cases

#### 1. Creating a New OFRAK Component

```
Create a new OFRAK unpacker component for XYZ format
```

The skill will:
- Generate the component following OFRAK patterns
- Create comprehensive tests
- Ensure proper type annotations
- Follow OFRAK coding standards

#### 2. Adding Tests

```
Add tests for the ExampleAnalyzer component
```

The skill will:
- Create test fixtures
- Write unit tests with 100% coverage
- Follow OFRAK testing conventions
- Use proper mocking and assertions

#### 3. Fixing Bugs

```
Fix the bug in the ELF unpacker where sections are not properly aligned
```

The skill will:
- Analyze the issue
- Implement the fix
- Add regression tests
- Maintain code coverage

#### 4. Writing OFRAK Scripts

```
Write a script to unpack and analyze all embedded resources in this firmware
```

The skill will:
- Use OFRAK APIs correctly
- Follow best practices
- Add proper error handling
- Include documentation

## What Makes This Different from the General OFRAK Skill?

This skill is specifically for **OFRAK contributors and developers**. It:
- Knows OFRAK internals and architecture
- Enforces 100% code coverage requirements
- Follows OFRAK contribution guidelines
- Uses OFRAK development patterns
- Understands the OFRAK codebase structure

For **using** OFRAK (not developing it), see the general `ofrak-user` skill.

## Skill Features

- ✅ Component development guidance
- ✅ Test generation with full coverage
- ✅ Code review against OFRAK standards
- ✅ Bug fixing with regression tests
- ✅ Documentation generation
- ✅ Type annotation enforcement

## Uninstalling

To remove the skill:

```bash
make uninstall
```

Or manually:

```bash
rm ~/.claude/skills/ofrak-developer
```

## Feedback

We want your feedback! Please open an issue on [OFRAK Github](https://github.com/redballoonsecurity/ofrak/issues).
