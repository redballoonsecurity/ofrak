# Unpackers
## Overview
Unpackers are responsible for logically partitioning a single binary target into constituent children. This often involves partitioning data in some way, but there is no limitation on what constitutes a valid child in respect to the parent's data.

Unpackers (and all components) target specific resource tags and typically unpack children with specific resource tags. For example, consider the following unpacker:

```python
from abc import ABC, abstractmethod

from ofrak.resource import Resource
from ofrak.component.unpacker import Unpacker

class IElfUnpacker(Unpacker[None], ABC):
    id = b"ElfUnpacker"
    targets = (Elf,)
    children = (
        ElfBasicHeader,
        ElfHeader,
        ElfProgramHeader,
        ElfSectionHeader,
        ElfSection,
        ElfStringSection,
        ElfSymbolSection,
        CodeRegion,
    )

    @abstractmethod
    async def unpack(self, resource: Resource, config=None):
        raise NotImplementedError()
```

This unpacker targets `Elf`. Its children must be one of: `ElfBasicHeader`, `ElfHeader`, `ElfProgramHeader`, `ElfSectionHeader`, `ElfSection`, `ElfStringSection`, `ElfSymbolSection`, `CodeRegion`.

Unpackers may at some point call other unpackers, or unpack descendants (children of children). For example, compressed file system unpackers can unpack a tree of children and descendants from one resource. These nested calls are fine.

## Usage
There are several ways in which unpackers can be invoked in OFRAK.

### Run Explicitly
The most direct way to run a specific unpacker is to run it directly against a resource. For example:

```python
from ofrak.resource import Resource
from ofrak_components.elf.unpacker import ElfUnpacker

...

resource: Resource
await resource.run(ElfUnpacker)
```

### Run Automatically
Unpackers can also be run automatically against resources with valid resource tags. For example, consider the following code:
```python
from ofrak.resource import Resource

...

resource: Resource
await resource.unpack()
```

If `resource` is an ELF, OFRAK will run the `IElfUnpacker` when this code is run. The reason for this is that `Resource.unpack` first runs all registered [identifiers](./identifier.md). Since the file is an ELF, it will be given the `Elf` tag, and OFRAK will then run the `IElfUnpacker`.

### Recursive Unpacking
It is also possible to chain `unpack` calls together recursively using the `Resource.unpack_recursively` method. See [Resource](../resource.md) for more details.

<div align="right">
<img src="../../assets/square_01.png" width="125" height="125">
</div>
