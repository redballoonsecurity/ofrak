from dataclasses import dataclass
from typing import Tuple, List

from ofrak.component.modifier import Modifier
from ofrak.core.memory_region import MemoryRegion
from ofrak.model.component_model import ComponentConfig
from ofrak.resource import Resource
from ofrak_type.range import Range


@dataclass
class BinaryInjectorModifierConfig(ComponentConfig):
    binary_patch_configs: List[Tuple[int, bytes]]


class BinaryInjectorModifier(Modifier[BinaryInjectorModifierConfig]):
    """
    Inject bytes at the given vm address in a [MemoryRegion][ofrak.core.memory_region.MemoryRegion].
    """

    targets = (MemoryRegion,)

    async def modify(self, resource: Resource, config: BinaryInjectorModifierConfig):
        assert config is not None
        memory_region = await resource.view_as(MemoryRegion)
        for vm_address, patch in config.binary_patch_configs:
            offset = memory_region.get_offset_in_self(vm_address)
            region_resource_data_id = memory_region.resource.get_data_id()
            if region_resource_data_id is None:
                raise ValueError(
                    "Cannot create DataPatch for a memory region resource with no " "data ID"
                )
            memory_region.resource.queue_patch(Range(offset, offset + len(patch)), patch)
