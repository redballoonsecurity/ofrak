from typing import Tuple, Optional

from ofrak.service.resource_service_i import ResourceFilter

from ofrak.resource import Resource

from ofrak.component.analyzer import Analyzer

from ofrak.core.architecture import ProgramAttributes
from ofrak.core.memory_region import MemoryRegion
from ofrak.core.program import Program
from ofrak.model.component_model import ComponentConfig


class MemoryRegionProgramAttributesAnalyzer(Analyzer[None, Tuple[ProgramAttributes]]):
    """
    Analyze a [MemoryRegion][ofrak.core.memory_region.MemoryRegion] to extract its
    [ProgramAttributes][ofrak.core.architecture.ProgramAttributes].
    """

    targets = (MemoryRegion,)
    outputs = (ProgramAttributes,)

    async def analyze(
        self, resource: Resource, config: Optional[ComponentConfig] = None
    ) -> Tuple[ProgramAttributes]:
        program_r = await resource.get_only_ancestor(ResourceFilter.with_tags(Program))
        program_attrs = await program_r.analyze(ProgramAttributes)
        return (program_attrs,)
