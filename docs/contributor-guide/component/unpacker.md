# Writing Unpackers

To write an OFRAK [Unpacker](../../user-guide/key-concepts/component/unpacker.md), an OFRAK contributor needs to:

1. Create a class that inherits from `ofrak.component.component_unpacker.Unpacker` with a defined component config (`ofrak.model.component_model.CC`);
2. Implement the `targets` to indicate what resource tags the unpacker targets (if necessary, [register a new identifier pattern](./identifier.md));
3. Implement `children` to indicate what resource tags are valid children that the unpacker can create;
4. Implement the `unpack` method such that it unpacks the resource into children.

The following is an example of a fully-implemented OFRAK unpacker:

```python
from dataclasses import dataclass

from ofrak.component.unpacker import Unpacker
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


class UImageUnpacker(Unpacker[None]):
    """
    UImage unpacker.

    It separates the UImage resource into its 2 parts: the header, and the body.
    """
    id = b"UImageUnpacker"
    targets = (UImage,)
    children = (UImageHeader, UImageBody)

    async def unpack(self, resource: Resource, config=None):
        uimage_header_r = await resource.create_child(
            tags=(UImageHeader,), data_range=Range(0, UIMAGE_HEADER_LEN)
        )
        uimage_header = await uimage_header_r.view_as(UImageHeader)
        await resource.create_child(
            tags=(UImageBody,),
            data_range=Range.from_size(UIMAGE_HEADER_LEN, uimage_header.ih_size),
        )
```

This unpacker targets a `UImage` and unpacks two possible children: a `UImageHeader` and `UImageBody`.



### Handling External Dependencies

If the Unpacker makes use of tools that are not packaged in modules installable via `pip` from 
PyPI (commonly command-line tools), these dependencies must be explicitly declared as part of the 
unpacker's class declaration. See the [Components Using External Tools](./external_tools.md) doc for 
information on how to do that.

<div align="right">
<img src="../../assets/square_02.png" width="125" height="125">
</div>
