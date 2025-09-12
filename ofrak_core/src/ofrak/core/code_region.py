from abc import ABC, abstractmethod

from ofrak.component.unpacker import Unpacker
from ofrak.core.complex_block import ComplexBlock
from ofrak.core.memory_region import MemoryRegion
from ofrak.resource import Resource


class CodeRegion(MemoryRegion):
    """
    A memory region within a [program][ofrak.core.program.Program] that contains executable code.
    """


class CodeRegionUnpacker(Unpacker[None], ABC):
    """
    Unpack a [code region][ofrak.core.code_region.CodeRegion] into
    [complex blocks][ofrak.core.complex_block.ComplexBlock].
    """

    targets = (CodeRegion,)
    children = (ComplexBlock,)
    id = b"CodeRegionUnpacker"

    @abstractmethod
    async def unpack(self, resource: Resource, config=None):
        """
        Unpack a code region, extracting all of the complex blocks within it.

        The bounds of these complex blocks should include any trailing data literals which are
        considered part of the complex block only if there are only data references to them from
        within that complex block.

        :param resource: the code region resource
        :param config:

        :raises ComplexBlockStructureError: if the unpacker tries to define a complex block which
        did not match our expectations of complex block structure
        """
        raise NotImplementedError()
