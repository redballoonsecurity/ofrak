from abc import ABC, abstractmethod
from dataclasses import dataclass
from itertools import chain
from typing import Tuple, Union, Iterable, Optional, Dict

from ofrak.model.viewable_tag_model import AttributesType
from ofrak_type.range import Range
from ofrak.model.resource_model import ResourceAttributes
from ofrak.model.tag_model import ResourceTag
from ofrak.core.architecture import ProgramAttributes
from ofrak.core.addressable import Addressable
from ofrak.core.memory_region import MemoryRegion
from ofrak.core.code_region import CodeRegion
from ofrak.core.program import Program
from ofrak import OFRAKContext
from ofrak.resource import Resource


class IFlattenedResource(ABC):
    @abstractmethod
    async def inflate(
        self,
        ofrak: OFRAKContext,
        parent: Optional[Resource] = None,
    ) -> Tuple[Resource, Dict[str, bytes]]:
        raise NotImplementedError


class FlattenedResource(IFlattenedResource):
    def __init__(
        self,
        tags: Tuple[ResourceTag, ...],
        attributes: Tuple[ResourceAttributes, ...],
        children: Iterable["IFlattenedResource"] = (),
        data: Union[bytes, Range, None] = None,
        # Common attributes, make it easier to look up,
        vaddr_and_size: Optional[Tuple[int, int]] = None,
        mark: Optional[str] = None,
    ):
        self.tags = tags

        self.children = children
        self.data: Union[bytes, Range, None] = data
        # When inflating recursively, you might want to be able to directly access one of the
        # inflated resources
        # If this argument is passed in, the dict returned by `inflate` will have (key: value) pair
        # for (`mark`: id of this resource)
        self.mark = mark
        self.vaddr_and_size = vaddr_and_size

        if vaddr_and_size is not None:
            vaddr, size = vaddr_and_size
            attributes = tuple(
                chain(
                    attributes,
                    (AttributesType[Addressable](vaddr), AttributesType[MemoryRegion](size)),
                )
            )

            if data is None:
                self.data: Union[bytes, Range, None] = b"\x00" * size
        self.attributes = attributes

    async def inflate(
        self,
        ofrak: OFRAKContext,
        parent: Optional[Resource] = None,
    ) -> Tuple[Resource, Dict[str, bytes]]:
        if parent:
            if type(self.data) is bytes:
                new_r = await parent.create_child(self.tags, self.attributes, data=self.data)
            elif type(self.data) is Range:
                new_r = await parent.create_child(self.tags, self.attributes, data_range=self.data)
            else:
                raise TypeError(f"Type of data must be bytes or Range (got {type(self.data)})")

        else:
            if type(self.data) is bytes:
                new_r = await ofrak.create_root_resource("test_resource", self.data)
                for attr in self.attributes:
                    new_r.add_attributes(attr)

                new_r.add_tag(*self.tags)
            else:
                raise TypeError(
                    f"When not passing in a parent, type of data must be bytes (got "
                    f"{type(self.data)})"
                )

        marked_resources = dict()
        if self.mark:
            marked_resources[self.mark] = new_r.get_id()

        await new_r.save()

        for child in self.children:
            _, child_marked_resources = await child.inflate(ofrak, new_r)

            marked_resources.update(child_marked_resources)

        return new_r, marked_resources


@dataclass
class FlattenedCodeRegion(IFlattenedResource):
    start_vaddr: int
    resources: Tuple[FlattenedResource, ...]
    padding_data: Tuple[Tuple[int, bytes], ...]
    mark: Optional[str] = None

    def get_combined_data(self) -> bytes:
        ordered_data_blocks: Iterable[Tuple[int, int, bytes]] = sorted(
            chain(
                [
                    (
                        flat_r.vaddr_and_size[0],
                        flat_r.vaddr_and_size[1],
                        flat_r.data if flat_r.data else b"\x00" * flat_r.vaddr_and_size[1],
                    )
                    for flat_r in self.resources
                ],
                [(vaddr, len(d), d) for vaddr, d in self.padding_data],
            ),
            key=lambda vaddr_size_data: vaddr_size_data[0],
        )

        combined_data = b""
        for data_block, next_data_block in zip(
            ordered_data_blocks, chain(ordered_data_blocks[1:], (None,))
        ):
            current_vaddr, current_size, current_data = data_block
            combined_data += current_data

            if next_data_block:
                next_vaddr, _, _ = next_data_block

                gap = next_vaddr - (current_vaddr + current_size)

                if gap < 0:
                    raise ValueError("The data blocks in the code region overlap")
                elif gap > 0:
                    combined_data += b"\x00" * gap

        return combined_data

    async def inflate(
        self,
        ofrak: OFRAKContext,
        parent: Optional[Resource] = None,
    ) -> Tuple[Resource, Dict[str, bytes]]:
        if parent is None:
            data = self.get_combined_data()
            size = len(data)
        else:
            _data = await parent.get_data_range_within_parent()
            data = _data.translate(-_data.start)
            size = data.length()

        # The combined data includes the data of the flattened resource, BUT...
        # Each inflated child resource of the code region has a copy of that data, since they
        # don't define their data as a mapping of the parent's data.

        flattened_code_region = FlattenedResource(
            (CodeRegion,),
            (),
            self.resources,
            data,
            vaddr_and_size=(self.start_vaddr, size),
            mark=self.mark,
        )

        inflated_code_r, marked_resource_ids = await flattened_code_region.inflate(ofrak, parent)

        return inflated_code_r, marked_resource_ids


@dataclass
class FlattenedProgram(IFlattenedResource):
    program_attributes: ProgramAttributes
    code_region: FlattenedCodeRegion

    async def inflate(
        self,
        ofrak: OFRAKContext,
        parent: Optional[Resource] = None,
    ) -> Tuple[Resource, Dict[str, bytes]]:
        cr_data = self.code_region.get_combined_data()

        flattened_program = FlattenedResource(
            (Program,),
            (self.program_attributes,),
            (self.code_region,),
            cr_data,
        )

        inflated_program_r, marked_resource_ids = await flattened_program.inflate(ofrak, parent)

        return inflated_program_r, marked_resource_ids
