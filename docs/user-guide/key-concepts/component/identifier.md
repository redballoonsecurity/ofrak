# Identifiers
## Overview
Identifiers are components that tag resources with specific resource tags.

The most ubiquitous identifier is the [MagicIdentifier][ofrak.core.magic.MagicIdentifier].


## Usage
Identifiers can be explicitly run using the `Resource.identify` method:
```python
await resource.identify()
```

Note that running identifiers explicitly is often not needed, as `Resource.unpack` runs all registered identifiers before running
[unpackers](unpacker.md).

<div align="right">
<img src="../../../assets/square_05.png" width="125" height="125">
</div>
