# Registering Identifier Patterns
When [writing unpackers](./unpacker.md), OFRAK Contributors can leverage the `MagicMimeIdentifier` and `MagicDescriptionIdentifier` by registering mappings between resource tags and mime or description patterns. Doing so will ensure that `Resource.unpack` automatically calls their custom unpacker.

For example, consider the following magic description identification registration in the file containing a `UImageUnpacker`:

```python
MagicDescriptionIdentifier.register(UImage, lambda s: s.startswith("u-boot legacy uImage"))
```

This line ensures that the `MagicDescriptionIdentifier` adds a `UImage` tag to resources matching that description pattern. As a result, any unpackers targeting a `UImage` will automatically run when `Resource.unpack` is run.

<div align="right">
<img src="../../assets/square_01.png" width="125" height="125">
</div>
