# Adding Identifiers
OFRAK Contributors and Users can extend the tool's identification capability in one of two ways:

1. Extend the [MagicIdentifier][ofrak.core.magic.MagicIdentifier] by registering a new magic pattern match
2. Implement a new [Identifier][ofrak.component.identifier.Identifier]

## Extend the MagicIdentifier
First, consider extending the magic identifier by registering a new magic pattern match.
The [MagicIdentifier][ofrak.core.magic.MagicIdentifier] uses three pattern matchers:

- [MagicMimePattern][ofrak.core.magic.MagicMimePattern] allows users to register matches to magic's mime output
- [MagicDescriptionPattern][ofrak.core.magic.MagicDescriptionPattern] allows users to create matching functions that run on the magic description output
- [RawMagicPattern][ofrak.core.magic.RawMagicPattern] allows users to create custom raw byte matching patterns against a resource's binary data

Combining these pattern matching strategies can provide expanded identification coverage, particularly when libmagic's output contains false negatives.
For example, all three patterns are used to identify `DeviceTreeBlob`

```python
MagicMimePattern.register(DeviceTreeBlob, "Device Tree Blob")
MagicDescriptionPattern.register(DeviceTreeBlob, lambda s: "device tree blob" in s.lower())


def match_dtb_magic(data: bytes):
    if len(data) < 4:
        return False
    return data[:4] == DTB_MAGIC_BYTES


RawMagicPattern.register(DeviceTreeBlob, match_dtb_magic)
```

These patterns (along with all other identifier patterns) will get run when the [MagicIdentifier][ofrak.core.magic.MagicIdentifier] runs, adding a `DeviceTreeBlob` tag to matching resources.
See the docstrings for each pattern for implementation details.
Generally speaking, it makes sense to start with a magic mime or magic description pattern, implementing a raw magic pattern only when necessary. 

## Implement a New Identifier
Additionally, it is possible to implement a new [Identifier][ofrak.component.identifier.Identifier].
Doing so should be reserved for situations where extending the [MagicIdentifier][ofrak.core.magic.MagicIdentifier] is impractical.
The [ApkIdentifier][ofrak.core.apk.ApkIdentifier] is an example of a custom identifier implementation.

!!! warning
    Adding new identifiers should be done with care to minimize overall performance impact to OFRAK workflows.
    Try to carefully select the resource tags the identifier targets to minimize the frequency with which
    it is run: generally speaking, targeting `GenericBinary` with result in this identifier getting run on the largest
    number of possible resources. `ApkIdentifier` targets `JavaArchive` and `ZipArchive` only for this reason.

### Handling External Dependencies
If the Identifier makes use of tools that are not packaged in modules installable via `pip` from 
PyPI (commonly command-line tools), these dependencies must be explicitly declared as part of the 
identifier's class declaration. See the [Components Using External Tools](./external_tools.md) doc 
for information on how to do that.

<div align="right">
<img src="../../assets/square_01.png" width="125" height="125">
</div>
