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

This format is interesting because it has a different sized tail block as well as different delimiters to represent the type of block. The component is able to handle these different types of fields by providing attributes in `FlashAttributes` that also includes a `FlashEccAttributes`. We will describe the other parts of these attributes and how to use them later in this page.

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
A `FlashAttributes` must be provided in order to use the flash component. As with other aspects of OFRAK, this can be modified and overriden if it does not work specifically for your use case.

### `FlashAttributes`
The `FlashAttributes` is necessary for communicating the information necessary to understand your specific flash format. This is the definition of the dataclass:

```python
class FlashAttributes(ResourceAttributes):
    # Block formats must be ORDERED iterables
    data_block_format: Iterable[FlashField]
    header_block_format: Optional[Iterable[FlashField]] = None
    first_data_block_format: Optional[Iterable[FlashField]] = None
    last_data_block_format: Optional[Iterable[FlashField]] = None
    tail_block_format: Optional[Iterable[FlashField]] = None
    ecc_attributes: Optional[FlashEccAttributes] = None
    checksum_func: Optional[Callable[[Any], Any]] = None
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
FlashAttributes(
    data_block_format=[
        FlashField(FlashFieldType.DATA, 512),
        FlashField(FlashFieldType.ECC, 16),
    ],
)
```

The `ecc_attributes` is also important for any dumps that include ECC. You have the option of providing the algorithms for encoding, decoding, and correcting the data. In addition, this is where the magic and any delimiter bytes are specified. The definition:
```python
class FlashEccAttributes(ResourceAttributes):
    ecc_class: Optional[EccAlgorithm] = None
    ecc_magic: Optional[bytes] = None
    head_delimiter: Optional[bytes] = None
    first_data_delimiter: Optional[bytes] = None
    data_delimiter: Optional[bytes] = None
    last_data_delimiter: Optional[bytes] = None
    tail_delimiter: Optional[bytes] = None
```


### Running the component
It can be used like any other component after first tagging the resource as `FlashResource` and then adding the attributes:

```python
# Create root resource and tag
root_resource = await ofrak_context.create_root_resource_from_file(IN_FILE)
root_resource.add_tag(FlashResource)
await root_resource.save()

# Add our attributes
root_resource.add_attributes(CUSTOM_FLASH_ATTRIBUTES)
await root_resource.save()
```

We have included an example that unpacks a provided flash dump, makes a modification, and repacks it into the same format in [`Example 9: Flash Modification`](`/examples/ex9_flash_modification.html`).


<div align="right">
<img src="../../assets/square_02.png" width="125" height="125">
</div>
