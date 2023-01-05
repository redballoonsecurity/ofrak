import io
import struct
import zlib
from dataclasses import dataclass
from enum import Enum
from typing import Optional, Tuple, Iterable, List

from ofrak.component.analyzer import Analyzer
from ofrak.component.modifier import Modifier
from ofrak.component.packer import Packer
from ofrak.component.unpacker import Unpacker
from ofrak.core import ProgramAttributes, GenericBinary, MagicDescriptionIdentifier
from ofrak.model.component_model import ComponentConfig
from ofrak.model.resource_model import ResourceAttributes
from ofrak.resource import Resource
from ofrak.resource_view import ResourceView
from ofrak.service.resource_service_i import ResourceFilter
from ofrak_io.deserializer import BinaryDeserializer
from ofrak_type.architecture import InstructionSet
from ofrak_type.bit_width import BitWidth
from ofrak_type.endianness import Endianness
from ofrak_type.range import Range

UIMAGE_MAGIC = 0x27051956
UIMAGE_NAME_LEN = 32
UIMAGE_HEADER_LEN = 64  # Length of the UImage header in bytes


#####################
#       Enums       #
#####################
# Enums referenced from https://github.com/EmcraftSystems/u-boot/blob/master/include/image.h
class UImageType(Enum):
    INVALID = 0
    STANDALONE = 1
    KERNEL = 2
    RAMDISK = 3
    MULTI = 4
    FIRMWARE = 5
    SCRIPT = 6
    FILESYSTEM = 7
    FLATDT = 8
    KWBIMAGE = 9
    IMXIMAGE = 10


class UImageCompressionType(Enum):
    NONE = 0
    GZIP = 1
    BZIP2 = 2
    LZMA = 3
    LZO = 4


class UImageOperatingSystem(Enum):
    INVALID = 0
    OPENBSD = 1
    NETBSD = 2
    FREEBSD = 3
    BSD_4_4 = 4
    LINUX = 5
    SVR4 = 6
    ESIX = 7
    SOLARIS = 8
    IRIX = 9
    SCO = 10
    DELL = 11
    NCR = 12
    LYNXOS = 13
    VXWORKS = 14
    PSOS = 15
    QNX = 16
    U_BOOT = 17
    RTEMS = 18
    ARTOS = 19
    UNITY = 20
    INTEGRITY = 21


class UImageArch(Enum):
    INVALID = 0
    ALPHA = 1
    ARM = 2
    I386 = 3
    IA64 = 4
    MIPS = 5
    MIPS64 = 6
    PPC = 7
    S390 = 8
    SH = 9
    SPARC = 10
    SPARC64 = 11
    M68K = 12
    NIOS = 13
    MICROBLAZE = 14
    NIOS2 = 15
    BLACKFIN = 16
    AVR32 = 17
    ST200 = 18


#####################
#     RESOURCES     #
#####################
@dataclass
class UImageHeader(ResourceView):
    """UImage header.

    :var ih_magic: Image Header Magic Number, 4 bytes
    :var ih_hcrc: Image Header CRC Checksum (when this field itself is zeroed out), 4 bytes
    :var ih_time: Image Creation Timestamp, 4 bytes
    :var ih_size: Image Data Size, 4 bytes
    :var ih_load: Data Load  Address, 4 bytes
    :var ih_ep: Entry Point Address, 4 bytes
    :var ih_dcrc: Image Data CRC Checksum, 4 bytes
    :var ih_os: Operating System, 1 byte
    :var ih_arch: CPU architecture, 1 byte
    :var ih_type: Image Type, 1 byte
    :var ih_comp: Compression Type, 1 byte
    :var ih_name: Image Name, 32 bytes
    """

    ih_magic: int
    ih_hcrc: int
    ih_time: int
    ih_size: int
    ih_load: int
    ih_ep: int
    ih_dcrc: int
    ih_os: int
    ih_arch: int
    ih_type: int
    ih_comp: int
    ih_name: bytes

    def get_os(self) -> UImageOperatingSystem:
        return UImageOperatingSystem(self.ih_os)

    def get_arch(self) -> UImageArch:
        return UImageArch(self.ih_arch)

    def get_compression_type(self) -> UImageCompressionType:
        return UImageCompressionType(self.ih_comp)

    def get_type(self) -> UImageType:
        return UImageType(self.ih_type)

    def get_name(self) -> str:
        return str(self.ih_name)

    def get_data_size(self) -> int:
        return self.ih_size

    def get_load_vaddr(self) -> int:
        return self.ih_load

    def get_entry_point_vaddr(self) -> int:
        return self.ih_ep


@dataclass
class UImageMultiHeader(ResourceView):
    """
    UImage MULTI-type header holding sizes of bodies contained in the parent uimage
    The header size is unknown, and is calculated by the uboot loader by reading past the
    UImageHeader until it reaches a null dword (\x00\x00\x00\x00).
    """

    image_sizes: Tuple[int, ...]

    def get_image_sizes(self) -> Tuple[int, ...]:
        return self.image_sizes

    def get_number_of_bodies(self) -> int:
        return len(self.image_sizes)

    def get_multi_header_size(self) -> int:
        return (len(self.image_sizes) + 1) * 4


class UImageBody(GenericBinary):
    pass


class UImageTrailingBytes(GenericBinary):
    pass


@dataclass
class UImage(GenericBinary):
    """
    A UImage is an image file that has a U-Boot wrapper (installed by the mkimage utility), and
    contains 1 or more images for use by U-Boot during boot.

    The U-Boot wrapper, or UImageHeader is a 64-byte fixed size header which contains
    information about the included images, such as the OS type, loader information, hardware ISA,
    etc. as well as CRC32 integrity checks.

    The contained images, or UImageBodies, can be anything from other nested UImages, to
    filesystems, kernels, and scripts.

    Assuming the body of a UImage is a program, the following snippet outlines a way to tag and
    analyze it.
    Note the addition of a CodeRegion view with a virtual address obtained from the UImageHeader,
    as well as tagging the UImageBody as a Program.
    ```
    uimage = await resource.view_as(UImage)
    uimage_header = await uimage.get_header()
    uimage_bodies = await uimage.get_bodies()
    uimage_body = uimage_bodies[0]
    uimage_body.resource.add_view(
        CodeRegion(
            virtual_address=uimage_header.get_load_vaddr(),
            size=uimage_header.get_data_size(),
        )
    )
    uimage_body.resource.add_tag(Program)
    await uimage_body.resource.save()
    ```
    """

    async def get_header(self) -> UImageHeader:
        return await self.resource.get_only_child_as_view(
            UImageHeader,
            ResourceFilter.with_tags(UImageHeader),
        )

    async def get_multi_header(self) -> UImageMultiHeader:
        return await self.resource.get_only_child_as_view(
            UImageMultiHeader, ResourceFilter.with_tags(UImageMultiHeader)
        )

    async def get_bodies(self) -> Iterable[UImageBody]:
        return await self.resource.get_children_as_view(
            UImageBody,
            ResourceFilter.with_tags(UImageBody),
        )


####################
#    UNPACKERS     #
####################
class UImageUnpacker(Unpacker[None]):
    """
    UImage unpacker.

    It unpacks the UImage resource into:
     - A 64-byte UImageHeader
     - [Optional] UImageMultiHeader (for UImageTypes.MULTI images)
     - A list of UImageBody instances (1 or many)
     - [Optional] UImageTrailingBytes (if any)
    """

    id = b"UImageUnpacker"
    targets = (UImage,)
    children = (
        UImageHeader,
        UImageMultiHeader,
        UImageBody,
        UImageTrailingBytes,
    )

    async def unpack(self, resource: Resource, config=None):
        uimage_header_r = await resource.create_child(
            tags=(UImageHeader,), data_range=Range(0, UIMAGE_HEADER_LEN)
        )
        uimage_header = await uimage_header_r.view_as(UImageHeader)
        resource_data = await resource.get_data()
        if uimage_header.get_type() == UImageType.MULTI:
            uimage_multi_size = resource_data[UIMAGE_HEADER_LEN:].find(b"\x00" * 4) + 4
            await resource.create_child(
                tags=(UImageMultiHeader,),
                data=resource_data[UIMAGE_HEADER_LEN : UIMAGE_HEADER_LEN + uimage_multi_size],
            )
            uimage_multi_header = await resource.get_only_child_as_view(
                UImageMultiHeader, ResourceFilter.with_tags(UImageMultiHeader)
            )

            image_i_start = UIMAGE_HEADER_LEN + uimage_multi_size
            for image_size in uimage_multi_header.get_image_sizes():
                await resource.create_child(
                    tags=(UImageBody,),
                    data=resource_data[image_i_start : image_i_start + image_size],
                )
                image_i_start += image_size

            total_len_with_bodies = (
                UIMAGE_HEADER_LEN
                + uimage_multi_header.get_multi_header_size()
                + sum(uimage_multi_header.get_image_sizes())
            )
            if total_len_with_bodies < uimage_header.ih_size:
                await resource.create_child(
                    tags=(UImageTrailingBytes,), data=resource_data[total_len_with_bodies:]
                )
        else:
            await resource.create_child(
                tags=(UImageBody,),
                data=resource_data[UIMAGE_HEADER_LEN:],
            )


#####################
#     ANALYZERS     #
#####################
class UImageHeaderAttributesAnalyzer(Analyzer[None, UImageHeader]):
    """
    Analyze the UImageHeader of a UImage
    """

    targets = (UImageHeader,)
    outputs = (UImageHeader,)

    async def analyze(self, resource: Resource, config=None) -> UImageHeader:
        tmp = await resource.get_data()
        deserializer = BinaryDeserializer(
            io.BytesIO(tmp),
            endianness=Endianness.BIG_ENDIAN,
            word_size=4,
        )

        deserialized = deserializer.unpack_multiple(f"IIIIIIIBBBB{UIMAGE_NAME_LEN}s")
        (
            ih_magic,
            ih_hcrc,
            ih_time,
            ih_size,
            ih_load,
            ih_ep,
            ih_dcrc,
            ih_os,
            ih_arch,
            ih_type,
            ih_comp,
            ih_name,
        ) = deserialized

        assert ih_magic == UIMAGE_MAGIC

        return UImageHeader(
            ih_magic,
            ih_hcrc,
            ih_time,
            ih_size,
            ih_load,
            ih_ep,
            ih_dcrc,
            ih_os,
            ih_arch,
            ih_type,
            ih_comp,
            ih_name,
        )


class UImageMultiHeaderAttributesAnalyzer(Analyzer[None, UImageMultiHeader]):
    """
    Analyze the UImageMultiHeader of a UImageType.MULTI UImage
    """

    targets = (UImageMultiHeader,)
    outputs = (UImageMultiHeader,)

    async def analyze(self, resource: Resource, config=None) -> UImageMultiHeader:
        resource_data = await resource.get_data()
        deserializer = BinaryDeserializer(
            io.BytesIO(resource_data),
            endianness=Endianness.BIG_ENDIAN,
            word_size=4,
        )
        uimage_multi_header_size = (len(resource_data) - 4) // 4  # Remove trailing null dword
        deserialized = deserializer.unpack_multiple(f"{uimage_multi_header_size}I")
        return UImageMultiHeader(deserialized)


class UImageProgramAttributesAnalyzer(Analyzer[None, Tuple[ProgramAttributes]]):
    """
    Analyze the ProgramAttributes of a UImage from its header
    """

    targets = (UImage,)
    outputs = (ProgramAttributes,)

    async def analyze(self, resource: Resource, config=None) -> Tuple[ProgramAttributes]:
        uimage_view = await resource.view_as(UImage)
        uimage_header = await uimage_view.get_header()
        uimage_program_attributes = self.from_deserialized_header(uimage_header)
        return (uimage_program_attributes,)

    @staticmethod
    def from_deserialized_header(
        header: UImageHeader,
    ) -> ProgramAttributes:
        UIMAGE_ARCH_TO_ISA = {
            UImageArch.ARM: InstructionSet.ARM,
            UImageArch.I386: InstructionSet.X86,
            UImageArch.IA64: InstructionSet.X86,
            UImageArch.MIPS: InstructionSet.MIPS,
            UImageArch.MIPS64: InstructionSet.MIPS,
            UImageArch.PPC: InstructionSet.PPC,
        }

        UIMAGE_ARCH_TO_BIT_WIDTH = {
            UImageArch.ARM: BitWidth.BIT_32,
            UImageArch.I386: BitWidth.BIT_32,
            UImageArch.IA64: BitWidth.BIT_64,
            UImageArch.MIPS: BitWidth.BIT_32,
            UImageArch.MIPS64: BitWidth.BIT_64,
            UImageArch.PPC: BitWidth.BIT_32,
        }

        UIMAGE_ARCH_TO_ENDIANNESS = {
            UImageArch.ARM: Endianness.LITTLE_ENDIAN,
            UImageArch.I386: Endianness.LITTLE_ENDIAN,
            UImageArch.IA64: Endianness.LITTLE_ENDIAN,
            UImageArch.PPC: Endianness.BIG_ENDIAN,
        }

        uimage_arch = UImageArch(header.ih_arch)

        try:
            isa = UIMAGE_ARCH_TO_ISA[uimage_arch]
            bit_width = UIMAGE_ARCH_TO_BIT_WIDTH[uimage_arch]
            endianness = UIMAGE_ARCH_TO_ENDIANNESS[uimage_arch]
        except ValueError:
            raise NotImplementedError(
                f"Unsupported/unknown uImage architecture: {uimage_arch.name}"
            )

        return ProgramAttributes(isa, None, bit_width, endianness, None)


####################
#    MODIFIERS     #
####################
@dataclass
class UImageHeaderModifierConfig(ComponentConfig):
    """
    Modifier config for a UImageHeader.

    The following field is not modifiable:
    - Image Header Magic Number (a constant)

    The following field is modifiable, but will be overwritten by the modifier:
    - Image Header CRC Checksum (`ih_hcrc`)

    The following fields are modifiable, but will be overwritten by the packer:
    - Image Data Size (`ih_size`)
    - Image Data CRC Checksum (`ih_dcrc`)
    """

    ih_hcrc: Optional[int] = None
    ih_time: Optional[int] = None
    ih_size: Optional[int] = None
    ih_load: Optional[int] = None
    ih_ep: Optional[int] = None
    ih_dcrc: Optional[int] = None
    ih_os: Optional[int] = None
    ih_arch: Optional[int] = None
    ih_type: Optional[int] = None
    ih_comp: Optional[int] = None
    ih_name: Optional[bytes] = None


class UImageHeaderModifier(Modifier[UImageHeaderModifierConfig]):
    """
    Modify a UImageHeader according to a given modifier config.
    Updates the header CRC field (`ih_hcrc`).
    """

    targets = (UImageHeader,)

    async def modify(self, resource: Resource, config: UImageHeaderModifierConfig) -> None:
        original_attributes = await resource.analyze(UImageHeader.attributes_type)
        # First serialize the header with the ih_hcrc field set to 0, to compute this CRC later
        new_attributes = ResourceAttributes.replace_updated(original_attributes, config)
        tmp_serialized_header = await UImageHeaderModifier.serialize(new_attributes, ih_hcrc=0)
        # Patch this header with its CRC32 in the ih_hcrc field
        ih_hcrc = zlib.crc32(tmp_serialized_header)
        serialized_header = await UImageHeaderModifier.serialize(new_attributes, ih_hcrc=ih_hcrc)
        resource.queue_patch(Range.from_size(0, UIMAGE_HEADER_LEN), serialized_header)
        new_attributes = ResourceAttributes.replace_updated(
            new_attributes, UImageHeaderModifierConfig(ih_hcrc=ih_hcrc)
        )
        resource.add_attributes(new_attributes)

    @staticmethod
    async def serialize(
        updated_attributes: UImageHeader.attributes_type, ih_hcrc: int = 0  # type: ignore
    ) -> bytes:
        """
        Serialize `updated_attributes` into bytes, using `ih_hcrc` for the eponymous field.
        This method doesn't perform any check or compute any CRC.
        """
        return struct.pack(
            f"!IIIIIIIBBBB{UIMAGE_NAME_LEN}s",
            UIMAGE_MAGIC,
            ih_hcrc,
            updated_attributes.ih_time,
            updated_attributes.ih_size,
            updated_attributes.ih_load,
            updated_attributes.ih_ep,
            updated_attributes.ih_dcrc,
            updated_attributes.ih_os,
            updated_attributes.ih_arch,
            updated_attributes.ih_type,
            updated_attributes.ih_comp,
            updated_attributes.ih_name,
        )


@dataclass
class UImageMultiHeaderModifierConfig(ComponentConfig):
    """
    Modifier config for a UImageMultiHeader.
    """

    image_sizes: List[int]


class UImageMultiHeaderModifier(Modifier[UImageMultiHeaderModifierConfig]):
    """
    Modify a UImageMultiHeader according to a given modifier config.
    """

    targets = (UImageMultiHeader,)

    async def modify(self, resource: Resource, config: UImageMultiHeaderModifierConfig) -> None:

        # # First serialize the header with the ih_hcrc field set to 0, to compute this CRC later
        original_attributes = await resource.analyze(UImageMultiHeader.attributes_type)
        new_attributes = ResourceAttributes.replace_updated(original_attributes, config)
        serialized_multiheader = await UImageMultiHeaderModifier.serialize(new_attributes)
        uimage_multi_header = await resource.view_as(UImageMultiHeader)
        resource.queue_patch(
            Range(0, uimage_multi_header.get_multi_header_size()),
            serialized_multiheader,
        )
        resource.add_attributes(new_attributes)

    @staticmethod
    async def serialize(
        updated_attributes: UImageMultiHeader.attributes_type,  # type: ignore
    ) -> bytes:
        """
        Serialize `updated_attributes` into bytes
        """
        serialized = b""
        for image_size in updated_attributes.image_sizes:
            serialized += struct.pack("!I", image_size)
        serialized += b"\x00" * 4
        return serialized


####################
#     PACKERS      #
####################
class UImagePacker(Packer[None]):
    """
    UImage packer.

    It patches the resource's UImageHeader and UImageBody instances into a single binary,
    updating the CRC checksums and image data size in the UImageHeader.
    Also handles the UImageMultiHeader in the case of UImageTypes.MULTI UImages.
    """

    id = b"UImagePacker"
    targets = (UImage,)

    async def pack(self, resource: Resource, config=None):
        repacked_body_data = b""
        uimage_view = await resource.view_as(UImage)
        header = await uimage_view.get_header()
        if header.get_type() == UImageType.MULTI:
            image_sizes = []
            for uimage_body in await uimage_view.get_bodies():
                image_sizes.append(await uimage_body.resource.get_data_length())
            multi_header = await uimage_view.get_multi_header()
            multiheader_modifier_config = UImageMultiHeaderModifierConfig(image_sizes=image_sizes)
            await multi_header.resource.run(UImageMultiHeaderModifier, multiheader_modifier_config)
            repacked_body_data += await multi_header.resource.get_data()
        for uimage_body in await uimage_view.get_bodies():
            repacked_body_data += await uimage_body.resource.get_data()

        # If there are UImageTrailingBytes, get them as well.
        resource_children = await resource.get_children()
        if any([child.has_tag(UImageTrailingBytes) for child in resource_children]):
            trailing_bytes_r = await resource.get_only_child_as_view(
                UImageTrailingBytes, ResourceFilter.with_tags(UImageTrailingBytes)
            )
            repacked_body_data += await trailing_bytes_r.resource.get_data()
        ih_size = len(repacked_body_data)
        ih_dcrc = zlib.crc32(repacked_body_data)
        header_modifier_config = UImageHeaderModifierConfig(ih_size=ih_size, ih_dcrc=ih_dcrc)
        await header.resource.run(UImageHeaderModifier, header_modifier_config)
        # Patch UImageHeader data
        header_data = await header.resource.get_data()
        # Patch all other data
        original_size = await resource.get_data_length()
        resource.queue_patch(Range(0, original_size), header_data + repacked_body_data)


MagicDescriptionIdentifier.register(UImage, lambda s: s.startswith("u-boot legacy uImage"))
