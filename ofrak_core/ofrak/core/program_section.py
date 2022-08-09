from dataclasses import dataclass

from ofrak.core.memory_region import MemoryRegion
from ofrak.model.resource_model import index


@dataclass
class ProgramSection(MemoryRegion):
    """
    A section of a program.

    :ivar virtual_address: The virtual address at the start of the section
    :ivar size: The size of the section in bytes
    """


@dataclass
class NamedProgramSection(ProgramSection):
    """
    A section of a program with a name.

    :ivar virtual_address: The virtual address at the start of the section
    :ivar size: The size of the section in bytes
    :ivar name: The name of the section
    """

    name: str

    @index
    def SectionName(self) -> str:
        return self.name

    @classmethod
    def caption(cls, all_attributes) -> str:
        try:
            namedprogram_attributes = all_attributes[NamedProgramSection.attributes_type]
        except KeyError:
            return super().caption(all_attributes)
        return f"{str(cls.__name__)}: {namedprogram_attributes.name}"


@dataclass
class ProgramSegment(MemoryRegion):
    """
    A segment of a program.

    :ivar virtual_address: The virtual address at the start of the segment
    :ivar size: The size of the segment in bytes
    """
