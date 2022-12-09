# Writing Packers
To write an OFRAK [Packer](../../user-guide/component/packer.md), an OFRAK contributor needs to:

1. Create a class that inherits from `ofrak.component.component_packer.Packer` with a defined component config (`ofrak.model.component_model.CC` -- this will typically be `None`);
2. Implement the `targets` to indicate what resource tags the packer targets;
3. Implement the `pack` method such that it correctly packs the resource's children or descendants.

The following is an example of a fully implemented OFRAK packer:

```python
from dataclasses import dataclass

from ofrak.component.packer import Packer
from ofrak.service.resource_service_i import ResourceFilter
from ofrak.core.binary import GenericBinary
from ofrak.resource import Resource
from ofrak_type.range import Range

[ ... ]

@dataclass
class UImage(GenericBinary):
    async def get_header(self) -> UImageHeader:
        return await self.resource.get_only_child_as_view(
            UImageHeader, ResourceFilter.with_tags(UImageHeader)
        )

    async def get_body(self) -> UImageBody:
        return await self.resource.get_only_child_as_view(
            UImageBody, ResourceFilter.with_tags(UImageBody),
        )


[ ... ]


class UImagePacker(Packer[None]):
    """
    UImage packer.

    It patches the resource's header and body into a single binary, updating the CRC
    checksums and image data size in the header.
    """

    id = b"UImagePacker"
    targets = (UImage,)

    async def pack(self, resource: Resource, config=None):
        uimage_view = await resource.view_as(UImage)
        header = await uimage_view.get_header()
        uimage_body = await uimage_view.get_body()
        # Modify the header with the data size and CRC32
        uimage_body_bytes = await uimage_body.resource.get_data()
        ih_size = len(uimage_body_bytes)
        ih_dcrc = zlib.crc32(uimage_body_bytes)
        header_modifier_config = UImageHeaderModifierConfig(ih_size=ih_size, ih_dcrc=ih_dcrc)
        await header.resource.run(UImageHeaderModifier, header_modifier_config)
        resource.queue_patch(Range.from_size(UIMAGE_HEADER_LEN, ih_size), uimage_body_bytes)
```

This packer targets a `UImage` and repacks a `UImageBody` with updated `UImageHeader` values.


### Handling External Dependencies

If the Packer makes use of tools that are not packaged in modules installable via `pip` from 
PyPI (commonly command-line tools), these dependencies must be explicitly declared as part of the 
packer's class declaration. See the [Components Using External Tools](./external_tools.md) doc for 
information on how to do that.

<div align="right">
<img src="../../assets/square_01.png" width="125" height="125">
</div>
