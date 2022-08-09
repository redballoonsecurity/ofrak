# Packers
## Overview
Packers are components that typically mirror unpackers, taking constituent children resources (and sometimes descendants) and reassembling them to produce a new resource.

Packers target specific resource tags against which they can run, and are typically paired with unpackers. For example, consider the `ZipPacker`:

```python
from io import BytesIO

from ofrak_type.range import Range

from ofrak.resource import Resource
from ofrak.component.packer import Packer

...

class ZipPacker(Packer[None]):
    targets = (ZipArchive,)

    async def pack(self, resource: Resource, config=None):
        zip_view: ZipArchive = await resource.view_as(ZipArchive)
        zip_entries = await zip_view.get_entries()

        result = BytesIO()
        with ZipFile(result, mode="w", compression=ZIP_DEFLATED) as zip_file:
            for zip_entry_view in zip_entries:
                zip_path_in_archive = zip_entry_view.path_in_archive
                zip_entry_data = await zip_entry_view.resource.get_data()
                zip_file.writestr(zip_path_in_archive, zip_entry_data)

        original_zip_size = await zip_view.resource.get_data_length()
        resource.queue_patch(Range(0, original_zip_size), result.getvalue())
```

This packer targets a `ZipArchive` and performs the opposite operation of `ZipUnpacker`.

Discerning OFRAK Users will notice that there are generally more unpackers than packers. The reason for this is that packers are often not needed in OFRAK when a child resource's data is mapped directly into its parent's data. For example, while there is an `IElfUnpacker` in OFRAK, an ELF packer is not needed: because all of an ELF's children are mapped directly into the ELF file, modifications to them are automatically reflected in the parent object. Note, however, that packers **are** needed in OFRAK when there are interdependencies between the data in children resources (a common example of this is when modifying the data of a child requires updating a checksum in another part of that resource).

## Usage
There are several ways in which a packer can be invoked in OFRAK.

### Run Explicitly
OFRAK packers can be run directly against a resource. For example:
```python
from ofrak.resource import Resource
from ofrak_components.zip import ZipPacker

...

resource: Resource
await resource.run(ZipPacker)
```

### Run Automatically
Packers can also be run automatically against resources with valid resource tags. For example, consider the following code:
```python
from ofrak.resource import Resource
from ofrak_components.zip import ZipArchive

...

resource: Resource
assert resource.has_tag(ZipArchive)
await resource.pack()
```

Since the resource has the `ZipArchive` tag, OFRAK will run the `ZipPacker`.

### Recursive Packing
It is also possible to chain `pack` calls together recursively using the `Resource.pack_recursively` method. See [Resource](../resource.md) for more details.

<div align="right">
<img src="../../assets/square_04.png" width="125" height="125">
</div>
