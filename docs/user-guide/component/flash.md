# Flash Component
## Overview
OFRAK includes a flash component that can unpack and pack a raw flash dump that includes out-of-band (OOB) data. A raw dump includes this extra data that make it hard to analyze without separating the "useful" data from the OOB data.

In this page, we will cover why we have this component, what a typical dump may look like, and how to get started with the flash component.

## A Typical Flash Dump
|    DATA   |    OOB   |    DATA   |    OOB   |    ...   |
| --------- | -------- | --------- | -------- | -------- |
| 512 Bytes | 16 Bytes | 512 Bytes | 16 Bytes |    ...   |

This pattern may continue for the entire flash chip or could have fields in the header or tail block that show the size of the region that includes OOB data.

Other examples are more complex. Sometimes this is because not all of the dump is ECC protected or needs OOB data so delimiters or magic bytes are necessary to show the area. An example format:

Header Block

| MAGIC | DATA | DELIMITER | ECC |
| ----- | ---- | --------- | --- |
| 7 bytes | 215 bytes | 1 byte | 32 bytes |

Data Block

| DATA | DELIMITER | ECC |
| ---- | --------- | --- |
| 222 bytes | 1 byte | 32 bytes |

Last Data Block

| DATA | DELIMITER | ECC |
| ---- | --------- | --- |
| 222 bytes | 1 byte | 32 bytes |

Tail Block

| DELIMITER | DATA SIZE | CHECKSUM | ECC |
| --------- | --------- | -------- | --- |
| 1 byte | 4 bytes | 16 bytes | 32 bytes |

This format is interesting because it has a different sized tail block as well as different delimiters to represent the type of block. The component is able to handle these different types of fields by providing a `FlashConfig` that also includes a `FlashEccConfig`. We will describe the other parts of these configs and how to use them later in this page.

### Types of Fields
In our experience, we have run into flash dumps that have included the following fields:
```python
class FlashFieldType(Enum):
    DATA = 0
    ECC = 1
    ALIGNMENT = 2
    MAGIC = 3
    DATA_SIZE = 4
    ECC_SIZE = 5
    CHECKSUM = 6
    DELIMITER = 7
    TOTAL_SIZE = 8
```

- `DATA` is the "useful" information in the dump.
- `ECC` are the most common OOB data with several common algorithms for verifying and correcting the data.
- `ALIGNMENT` can be used for padding to fill an entire block or page.
- `MAGIC` is in some dumps that are not entirely covered in OOB data. These bytes indicate the start of the OOB inclusive region.
- `DATA_SIZE` indicates the expected size of the `DATA`
- `ECC_SIZE` indicates the size of the `ECC` field.
- `CHECKSUM` ensures that the data is read as expected.
- `DELIMITER` may be placed between fields in a block or to indicate what type of block it is.
- `TOTAL_SIZE` indicates the size of the entire region that includes OOB data.

We recognize that some fields may be used differently than our implementation currently allows and we are likely missing some fields to be truly universal. In these cases, these classes can be overriden to be more flexible with your own use case.


## Usage
A `FlashConfig` must be provided in order to use the flash component. As with other aspects of OFRAK, this can be modified and overriden if it does not work specifically for your use case.

### `FlashConfig`
The `FlashConfig` is necessary for communicating the information necessary to understand your specific flash format. This is the definition of the dataclass:
```python
@dataclass
class FlashConfig(ComponentConfig):
    # Block formats must be ORDERED iterables
    data_block_format: Iterable[FlashField]
    header_block_format: Optional[Iterable[FlashField]] = None
    first_data_block_format: Optional[Iterable[FlashField]] = None
    last_data_block_format: Optional[Iterable[FlashField]] = None
    tail_block_format: Optional[Iterable[FlashField]] = None
    ecc_config: Optional[FlashEccConfig] = None
    checksum_func: Optional[Callable[[Any], Any]] = lambda x: md5(x).digest()
```
The only required field is the `data_block_format`. These block formats are specified using an *ordered* `Iterable[FlashField]` to describe the block:

```python
@dataclass
class FlashField:
    field_type: FlashFieldType
    size: int
```
This dataclass uses the previously shown `Enum` with our various field types. We just need to specify the field type and the size for each `FlashField` and provide them in order. An example:
```python
FlashConfig(
    data_block_format=[
        FlashField(FlashFieldType.DATA, 512),
        FlashField(FlashFieldType.CHECKSUM, 16),
    ],
)
```

The `ecc_config` is also important for any dumps that include ECC. You have the option of providing the algorithms for encoding, decoding, and correcting the data. In addition, this is where the magic and any delimiter bytes are specified. The definition:
```python
@dataclass
class FlashEccConfig(ComponentConfig):
    ecc_class: Callable[[Any], Any]
    ecc_magic: Optional[bytes] = None
    head_delimiter: Optional[bytes] = None
    first_data_delimiter: Optional[bytes] = None
    data_delimiter: Optional[bytes] = None
    last_data_delimiter: Optional[bytes] = None
    tail_delimiter: Optional[bytes] = None
```


### Making your own component
The preferred way to run the OFRAK flash component is to create your own component that includes a default `FlashConfig`. This allows you to leverage other parts of OFRAK like unpacking recursively, analyzing the contents, making modifications, and then packing it all back up into the same format. Below is an example for the previously mentioned format used in some Micron "small-page" flash chips.

```python
from ofrak import Resource, ResourceFilter
from ofrak_components.flash import (
    FlashOobResource,
    FlashResource,
    FlashHeaderBlock,
    FlashBlock,
    FlashTailBlock,
    FlashLogicalDataResource,
    FlashLogicalEccResource,
    FlashResourceUnpacker,
    FlashLogicalDataResourcePacker,
    FlashConfig,
    FlashField,
    FlashFieldType,
)

MICRON_FLASH_CONFIG = FlashConfig(
    data_block_format=[
        FlashField(FlashFieldType.DATA, 512),
        FlashField(FlashFieldType.CHECKSUM, 16),
    ],
)

class MicronNandUnpacker(FlashResourceUnpacker):
    id = b"MicronNandUnpacker"
    targets = (FlashResource,)
    children = (
        FlashOobResource,
        FlashHeaderBlock,
        FlashBlock,
        FlashTailBlock,
        FlashLogicalDataResource,
        FlashLogicalEccResource,
    )

    async def unpack(self, resource: Resource, config: FlashConfig = MICRON_FLASH_CONFIG):
        await resource.run(FlashResourceUnpacker, config=config)


class MicronNandPacker(FlashLogicalDataResourcePacker):
    id = b"MicronNandPacker"
    targets = (FlashLogicalDataResource,)

    async def pack(self, resource: Resource, config: FlashConfig = MICRON_FLASH_CONFIG):
        await resource.run(FlashLogicalDataResourcePacker, config=config)
```

To run this new component, you must first use the `ofrak.injector` to discover the new component. Then just create the root_resource and add the `FlashResource` tag. We are then free to use `auto_run_recursively` while blacklisting the existing implementation that does not have a default config.

```python
IN_FILE = "micron_flash_dump.bin"

from ofrak import OFRAK, OFRAKContext
from ofrak_components.flash import (
    FlashResource,
    FlashResourceUnpacker,
    FlashLogicalDataResourcePacker,
)
import micron_nand_component

async def main(ofrak_context: OFRAKContext):
    root_resource = await ofrak_context.create_root_resource_from_file(IN_FILE)
    root_resource.add_tag(FlashResource)
    await root_resource.save()
    await root_resource.auto_run_recursively(
        blacklisted_components=[
            FlashLogicalDataResourcePacker,
        ]
    )

if __name__ == "__main__":
    ofrak = OFRAK()
    ofrak.injector.discover(micron_nand_component)
    ofrak.run(main)
```

<div align="right">
<img src="../../assets/square_02.png" width="125" height="125">
</div>
