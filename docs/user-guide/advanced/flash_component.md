# NAND Flash Components
## Overview
OFRAK includes a flash component that can unpack and pack a raw flash dump that includes out-of-band (OOB) data. A raw dump includes this extra data that make it hard to analyze without separating the "useful" data from the OOB data.

This page covers what a typical flash dump may look like and how to get started with using the flash components.

## A Typical Flash Dump

A typical flash dump looks something like this:

|    DATA   |    OOB   |    DATA   |    OOB   |    ...   |
| --------- | -------- | --------- | -------- | -------- |
| 512 Bytes | 16 Bytes | 512 Bytes | 16 Bytes |    ...   |

This pattern may continue for the entire flash chip or could have fields in the header or tail block that show the size of the region that includes OOB data.

### Common Page Geometries

Real NAND dumps often use a handful of standard `(data, OOB)` page sizes, and the whole image is almost always a power-of-two number of pages:

| Data | OOB | Typical use |
| ---- | --- | ----------- |
| 512 | 16 | "Small-page" NAND (SLC, older parts) |
| 2048 | 64 | "Large-page" NAND — the most common modern geometry |
| 4096 | 128 | 4K-page NAND |
| 4096 | 224 | 4K-page NAND with extra OOB for stronger (BCH) ECC |
| 8192 | 448 | 8K-page NAND |
| 256 | 0 | SPI NOR / raw images with no spare area |

Which one you're looking at can usually be narrowed down from the file size alone: geometries where `data + OOB` evenly divides the image into a power-of-two page count are plausible candidates for a raw chip dump. 

### OOB Layout Conventions

The OOB (also called "spare area") of a page is not always random: different software stacks impose recognisable structures on it. The three conventions most commonly seen in the wild are:

**Linux MTD large-page (64-byte OOB)**

| Bytes | Contents |
| ----- | -------- |
| `[0, 40)` | Bad-block / scrub-marker region. On a good block these bytes are all `0xFF`; a non-`0xFF` byte 0 marks the block as bad. |
| `[40, 64)` | 24 bytes of Hamming ECC, arranged as 8 x 3-byte triplets covering 8 x 256-byte subpages of the data region. |

This layout assumes the data region is a multiple of 256 bytes (Linux's soft-Hamming sector size), so it fits naturally over 2048-byte pages (8 subpages) and smaller multiples of 256. 4K / 8K pages that follow this layout typically only cover the first 2048 bytes with Hamming and protect the rest with a different algorithm (e.g. BCH).

**YAFFS2 "packed tags 2"**

| Bytes | Contents |
| ----- | -------- |
| 0 | `0xFF` (leading erased byte, deliberately left untouched by YAFFS) |
| 1 | `0x55` — the YAFFS2 tag marker |
| `[2, 18)` | 16 bytes of little-endian packed tags: `(seq_number, object_id, chunk_id, n_bytes)` as 4 x `uint32`. |

Pages carrying YAFFS2 tags usually still include ECC in the remaining OOB bytes under the Linux MTD large-page convention, so a YAFFS2 OOB is a superset of the MTD layout with tags squeezed into the bad-block-marker region.

**Small-page OOB (<= 16 bytes)**

| Bytes | Contents |
| ----- | -------- |
| 5 | Bad-block marker — `0xFF` for good blocks, any other value indicates a bad block. |
| Other | ECC + metadata, densely populated. |

Classic 512+16 NAND follows this layout. 

### Erased Pages and Bad-Block Markers

Two byte-level conventions hold across essentially every NAND image and are useful to keep in mind when looking at a raw dump:

- **Erased flash reads as `0xFF`.** Before a block is programmed, every byte, data region *and* OOB, is `0xFF`. "Deletion" on NAND is a block-level erase that restores this state. 
- **A non-`0xFF` byte at the bad-block-marker offset** (byte 5 for small-page OOB, byte 0 of the scrub-marker region for large-page OOB) marks the whole block as unusable. Software stacks skip the block and relocate its data to a spare block. A bad block in a raw dump often still contains old data that looks populated but should be ignored.

### More Complex Layouts

Other examples are more complex. Sometimes this is due to the fact that not all of the dump is ECC protected or needs OOB data. In such cases, delimiters or magic bytes are necessary to show the area. An example format:

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

This format is interesting because it has a different sized tail block as well as different delimiters to represent the type of block. The [FlashUnpacker][ofrak.core.flash.FlashResourceUnpacker] is able to handle these different types of fields by providing attributes in [FlashAttributes][ofrak.core.flash.FlashAttributes] that also includes a [FlashEccAttributes][ofrak.core.flash.FlashEccAttributes]. We will describe the other parts of these attributes and how to use them later in this page.

### Types of Fields
The class [FlashFieldType][ofrak.core.flash.FlashFieldType] contains field types that are commonly encountered in flash dumps:
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
    SPARE = 9
    SPARE_SIZE = 10
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
- `SPARE` is opaque OOB data that should be preserved but not decoded or verified. When a block format contains a `SPARE` field, the unpacker concatenates the spare bytes from every block into a `FlashSpareAreaResource` sibling of `FlashLogicalDataResource`. The packer (`FlashLogicalDataResourcePacker`) reads this sibling resource and slices it back into per-block `SPARE` slots so the original OOB layout is reconstructed verbatim, even after modifying the logical data.
- `SPARE_SIZE` indicates the size of the `SPARE` field.

This class can be overridden or augmented if other field types are encountered.


## Usage
A [FlashAttributes][ofrak.core.flash.FlashAttributes] must be provided in order to use the flash component. As with other aspects of OFRAK, this can be modified and overridden if it does not work specifically for your use case.

### `FlashAttributes`
The [FlashAttributes][ofrak.core.flash.FlashAttributes] is necessary for communicating the information necessary to understand your specific flash format.

The only required field is the `data_block_format`. These block formats are specified using an *ordered* `Iterable[FlashField]` to describe the block.

This dataclass uses the previously shown `Enum` with our various field types. We just need to specify the field type and the size for each `FlashField` and provide them in order. An example:
```python
FlashAttributes(
    data_block_format=[
        FlashField(FlashFieldType.DATA, 512),
        FlashField(FlashFieldType.ECC, 16),
    ],
)
```

The `ecc_attributes` are also important for any dumps that include ECC. You have the option of providing the algorithms for encoding, decoding, and correcting the data. In addition, this is where the magic and any delimiter bytes are specified. See [FlashEccAttributes][ofrak.core.flash.FlashEccAttributes] for more information.


### Running the Flash components
The Flash components can be used like any other OFRAK components. The first step is to tag a resource as a [FlashResource][ofrak.core.flash.FlashResource] and tag it with its flash resource attributes:

```python
# Create root resource and tag
root_resource = await ofrak_context.create_root_resource_from_file(IN_FILE)
root_resource.add_tag(FlashResource)
await root_resource.save()

# Add our attributes
root_resource.add_attributes(CUSTOM_FLASH_ATTRIBUTES)
await root_resource.save()
```

See [Example 9: Flash Modification](https://ofrak.com/docs/examples/ex9_flash_modification.html) for example usage of these components.


<div align="right">
<img src="../../assets/square_02.png" width="125" height="125">
</div>
