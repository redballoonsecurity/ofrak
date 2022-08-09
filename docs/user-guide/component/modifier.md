# Modifiers
## Overview
Modifiers operate on the current state of the binary, directly manipulating the underlying binary data. When they do this, they invalidate the data and attribute dependencies for the modified resource.

The most basic modifier, outlined below, performs simple offset and content patching:

```python
@dataclass
class BinaryPatchConfig(ComponentConfig):
    offset: int  # Physical offset from beginning of resource
    bytes: bytes  # Raw bytes to patch


class BinaryPatchModifier(Modifier[BinaryPatchConfig]):
    """
    Patch the binary at the target offset with raw bytes.
    """

    targets = (ResourceTag,)

    async def modify(self, resource: Resource, config: BinaryPatchConfig) -> None:
        resource_size = await resource.get_data_length()
        if len(config.patch_bytes) > resource_size - config.offset:
            raise ModifierError(
                f"The binary patch, {config}, overflows the original size of the resource "
                f"{resource.get_id().hex()}."
            )
        return resource.queue_patch(config.get_range(), config.patch_bytes)
```

## Usage
Modifiers should be run directly against a resource. For example:
```python
patch_config = BinaryPatchConfig(100, b"Meow!")
await resource.run(BinaryPatchModifier, patch_config)
```

<div align="right">
<img src="../../assets/square_03.png" width="125" height="125">
</div>
