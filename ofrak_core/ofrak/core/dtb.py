"""
Device Tree Blob (or Flattened Device Tree) OFRAK Utilities
For more information see: https://devicetree-specification.readthedocs.io/en/stable/flattened-format.html
"""

import os
import struct
from dataclasses import dataclass
from enum import Enum
from typing import Union, List, Tuple

import fdt

from ofrak.component.analyzer import Analyzer
from ofrak.component.identifier import Identifier
from ofrak.component.packer import Packer
from ofrak.component.unpacker import Unpacker
from ofrak.resource import Resource
from ofrak.service.resource_service_i import ResourceFilter, ResourceSort
from ofrak.core import GenericBinary, MagicMimeIdentifier, MagicDescriptionIdentifier
from ofrak.model.component_model import CC
from ofrak.model.resource_model import index
from ofrak_type.range import Range

DTB_MAGIC_SIGNATURE: int = 0xD00DFEED


@dataclass
class DtbNode(GenericBinary):
    """
    Device Tree Node
    """

    name: str

    @index
    def DtbNodeName(self) -> str:
        return self.name

    @classmethod
    def caption(cls, attributes) -> str:
        try:
            dtb_attributes = attributes[DtbNode.attributes_type]
        except KeyError:
            return super().caption(attributes)
        return f"{cls.__name__}: {dtb_attributes.name}"

    async def get_path(self) -> str:
        """
        Get the path of a DtbNode within a DeviceTreeBlob.
        Root node is always "/" per DTB specifications.
        """
        if self.name == "/":
            return self.name

        parent_node = await self.resource.get_parent_as_view(v_type=DtbNode)
        return os.path.join(await parent_node.get_path(), self.name)


class DeviceTreeBlob(GenericBinary):
    """
    A Device Tree Blob (DTB).
    """

    async def get_node_by_path(self, path: str) -> DtbNode:
        descendants = await self.resource.get_descendants_as_view(
            v_type=DtbNode, r_filter=ResourceFilter.with_tags(DtbNode)
        )
        for node in descendants:
            d_path = await node.get_path()
            if d_path == path:
                return node
        raise ValueError(f"The path {path} does not correspond to a node")


@dataclass
class DtbHeader(GenericBinary):
    """
    Device Tree Header
    """

    dtb_magic: int
    totalsize: int
    off_dt_struct: int
    off_dt_strings: int
    off_mem_rsvmap: int
    version: int
    last_comp_version: int
    boot_cpuid_phys: int = 0
    size_dt_strings: int = 0
    size_dt_struct: int = 0


class DtbHeaderAnalyzer(Analyzer[None, DtbHeader]):
    """
    Analyze Device Tree Blob header information and return a DtbHeader
    """

    id = b"DtbHeaderAnalyzer"
    targets = (DtbHeader,)
    outputs = (DtbHeader,)

    async def analyze(self, resource: Resource, config: CC) -> DtbHeader:
        header_data = await resource.get_data()
        (
            dtb_magic,
            totalsize,
            off_dt_struct,
            off_dt_strings,
            off_mem_rsvmap,
            version,
            last_comp_version,
        ) = struct.unpack(">IIIIIII", header_data[:28])
        assert dtb_magic == DTB_MAGIC_SIGNATURE, (
            f"DTB Magic bytes not matching."
            f"Expected: {DTB_MAGIC_SIGNATURE} "
            f"Unpacked: {dtb_magic}"
        )
        boot_cpuid_phys = 0
        dtb_strings_size = 0
        dtb_struct_size = 0
        if version >= 2:
            boot_cpuid_phys = struct.unpack(">I", header_data[28:32])[0]
        if version >= 3:
            dtb_strings_size = struct.unpack(">I", header_data[32:36])[0]
        if version >= 17:
            dtb_struct_size = struct.unpack(">I", header_data[36:40])[0]

        return DtbHeader(
            dtb_magic,
            totalsize,
            off_dt_struct,
            off_dt_strings,
            off_mem_rsvmap,
            version,
            last_comp_version,
            boot_cpuid_phys,
            dtb_strings_size,
            dtb_struct_size,
        )


@dataclass
class DtbEntry(GenericBinary):
    """
    Device Tree Entry
    """

    address: int
    size: int


class DtbPropertyType(Enum):
    DtbPropNoValue = 0
    DtbInt = 1
    DtbStr = 2
    DtbBytes = 3
    DtbIntList = 4
    DtbStrList = 5


@dataclass
class DtbProperty(GenericBinary):
    """
    DTB Property
    """

    name: str
    p_type: DtbPropertyType

    @index
    def DtbPropertyName(self) -> str:
        return self.name

    @classmethod
    def caption(cls, attributes) -> str:
        try:
            dtb_attributes = attributes[DtbProperty.attributes_type]
        except KeyError:
            return super().caption(attributes)
        return f"{cls.__name__}: {dtb_attributes.name}"

    async def get_path(self):
        parent_node = await self.resource.get_parent_as_view(v_type=DtbNode)
        return os.path.join(await parent_node.get_path(), self.name)

    async def get_value(self) -> Union[str, List[str], int, List[int], bytes, bytearray, None]:
        if self.p_type is DtbPropertyType.DtbPropNoValue:
            return None
        elif self.p_type is DtbPropertyType.DtbBytes:
            return await self.resource.get_data()
        elif self.p_type is DtbPropertyType.DtbInt:
            return struct.unpack(">I", await self.resource.get_data())[0]
        elif self.p_type is DtbPropertyType.DtbIntList:
            data = await self.resource.get_data()
            return [
                struct.unpack(">I", i)[0] for i in [data[j : j + 4] for j in range(0, len(data), 4)]
            ]
        elif self.p_type is DtbPropertyType.DtbStr:
            data = await self.resource.get_data()
            return data.decode("ascii")
        elif self.p_type is DtbPropertyType.DtbStrList:
            data = await self.resource.get_data()
            return [s.decode("ascii") for s in data.split(b"\x00")]
        else:
            raise TypeError(f"Unsupported type {self.p_type} for property {self.name}")


class DeviceTreeBlobUnpacker(Unpacker[None]):
    """
    Unpacks a DeviceTreeBlob:

    A DeviceTreeBlob consists of:
    - 1 DtbHeader
    - 0 or more DtbEntry instances
    - 1 root DtbNode which can contain 0 or more DtbNode and DtbProperty children
    - Each DtbNode can have 0 or more DtbProperty children and 0 or more further nested DtbNode
        children in it
    """

    targets = (DeviceTreeBlob,)
    children = (
        DtbHeader,
        DtbEntry,
        DtbNode,
        DtbProperty,
    )

    async def unpack(self, resource: Resource, config: CC = None):
        dtb_data = await resource.get_data()
        dtb_view = await resource.view_as(DeviceTreeBlob)
        dtb = fdt.parse_dtb(dtb_data)

        # Create DtbHeader
        await resource.create_child(
            tags=(DtbHeader,),
            data=dtb.header.export(),
        )

        # Create DtbEntry instances
        for dtb_entry in dtb.entries:
            await resource.create_child_from_view(
                DtbEntry(
                    address=dtb_entry["address"],
                    size=dtb_entry["size"],
                ),
                data=b"",
            )

        # Create root node
        await resource.create_child_from_view(
            DtbNode(name=dtb.root.name),
            data=b"",
        )

        # Create DtbNode and DtbProperty instances and structure by walking the DeviceTreeBlob
        for path, nodes, props in dtb.walk():
            # Get parent
            parent_node = await dtb_view.get_node_by_path(path)
            for node in nodes:
                await parent_node.resource.create_child_from_view(DtbNode(name=node.name), data=b"")
            for prop in props:
                p_type, p_data = _prop_from_fdt(prop)

                await parent_node.resource.create_child_from_view(
                    DtbProperty(
                        name=prop.name,
                        p_type=p_type,
                    ),
                    data=p_data,
                )


class DeviceTreeBlobPacker(Packer[None]):
    """
    Device Tree Blob Packer

    Repacks the Device Tree Blob tree structure into the binary format and patches the original
    resource.
    """

    id = b"DeviceTreeBlobPacker"
    targets = (DeviceTreeBlob,)

    async def pack(self, resource: Resource, config: CC = None):
        header = fdt.Header()
        header_view = await resource.get_only_descendant_as_view(
            v_type=DtbHeader, r_filter=ResourceFilter(tags=[DtbHeader])
        )

        header.version = header_view.version
        header.total_size = header_view.totalsize
        header.off_dt_struct = header_view.off_dt_struct
        header.last_comp_version = header_view.last_comp_version
        header.boot_cpuid_phys = header_view.boot_cpuid_phys

        dtb = fdt.FDT(header=header)

        dtb.entries = [
            {"address": entry.address, "size": entry.size}
            for entry in await resource.get_descendants_as_view(
                v_type=DtbEntry, r_filter=ResourceFilter(tags=[DtbEntry])
            )
        ]

        root_node_view = await resource.get_only_child_as_view(
            DtbNode, r_filter=ResourceFilter(tags=[DtbNode])
        )
        dtb.root = fdt.Node(name=await root_node_view.get_path())
        for prop in await root_node_view.resource.get_children_as_view(
            v_type=DtbProperty,
            r_filter=ResourceFilter(tags=[DtbProperty]),
            r_sort=ResourceSort(DtbProperty.DtbPropertyName),
        ):
            dtb.add_item(await _prop_to_fdt(prop), await root_node_view.get_path())
        for node in await root_node_view.resource.get_descendants_as_view(
            v_type=DtbNode,
            r_filter=ResourceFilter(tags=[DtbNode]),
            r_sort=ResourceSort(DtbNode.DtbNodeName),
        ):
            # By default, add_item adds the missing nodes to complete the path of a previous node
            if not dtb.exist_node(await node.get_path()):
                dtb.add_item(fdt.Node(node.name), os.path.dirname(await node.get_path()))
            for prop in await node.resource.get_children_as_view(
                v_type=DtbProperty,
                r_filter=ResourceFilter(tags=[DtbProperty]),
                r_sort=ResourceSort(DtbProperty.DtbPropertyName),
            ):
                dtb.add_item(await _prop_to_fdt(prop), await node.get_path())
        original_size = await resource.get_data_length()
        resource.queue_patch(Range(0, original_size), dtb.to_dtb())


class DeviceTreeBlobIdentifier(Identifier[None]):
    """
    Identify Device Tree Blob files.
    """

    targets = (GenericBinary,)

    async def identify(self, resource: Resource, config: None) -> None:
        """
        Identify DTB files based on the first four bytes being "d00dfeed".
        """
        data = await resource.get_data(Range(0, 4))
        if data == struct.pack("<I", DTB_MAGIC_SIGNATURE):
            resource.add_tag(DeviceTreeBlob)


async def _prop_to_fdt(p: DtbProperty) -> fdt.items.Property:
    """
    Generates an fdt.items.property corresponding to a DtbProperty.
    :param p:
    :return:
    """
    value = await p.get_value()
    if p.p_type is DtbPropertyType.DtbPropNoValue:
        return fdt.items.Property(name=p.name)
    elif p.p_type is DtbPropertyType.DtbBytes:
        return fdt.items.PropBytes(name=p.name, data=await p.resource.get_data())
    elif p.p_type is DtbPropertyType.DtbInt:
        return fdt.items.PropWords(p.name, value)
    elif p.p_type is DtbPropertyType.DtbIntList:
        return fdt.items.PropWords(p.name, *value)
    elif p.p_type is DtbPropertyType.DtbStr:
        return fdt.items.PropStrings(p.name, value)
    elif p.p_type is DtbPropertyType.DtbStrList:
        return fdt.items.PropStrings(p.name, *value)
    else:
        raise TypeError(f"Unsupported type {p.p_type} for property {p.name}")


def _prop_from_fdt(p: fdt.items.Property) -> Tuple[DtbPropertyType, bytes]:
    """
    Converts an fdt.items.property to its p_type and p_data values.
    :param p:
    :return:
    """
    if type(p) is fdt.items.Property or len(p.data) == 0:
        _p_type = DtbPropertyType.DtbPropNoValue
        _p_data = b""
    elif type(p) is fdt.items.PropBytes:
        _p_type = DtbPropertyType.DtbBytes
        _p_data = bytes(p.data)
    elif isinstance(p.value, int):
        if len(p.data) == 1:
            _p_type = DtbPropertyType.DtbInt
        else:
            _p_type = DtbPropertyType.DtbIntList
        _p_data = b"".join([struct.pack(">I", i) for i in p.data])
    elif isinstance(p.value, str):
        if len(p.data) == 1:
            _p_type = DtbPropertyType.DtbStr
            _p_data = b"".join([s.encode("ascii") for s in p.data])
        else:
            _p_type = DtbPropertyType.DtbStrList
            _p_data = b"\0".join([s.encode("ascii") for s in p.data])

    else:
        raise TypeError(f"Unknown type for DTB Property: {p}")
    return _p_type, _p_data


MagicMimeIdentifier.register(DeviceTreeBlob, "Device Tree Blob")
MagicDescriptionIdentifier.register(DeviceTreeBlob, lambda s: "device tree blob" in s.lower())
