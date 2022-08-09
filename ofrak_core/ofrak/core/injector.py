from dataclasses import dataclass
from typing import Tuple, List

from ofrak.component.modifier import Modifier
from ofrak.core.memory_region import MemoryRegion
from ofrak.model.component_model import ComponentConfig
from ofrak.model.data_model import DataPatch
from ofrak.resource import Resource
from ofrak_type.range import Range


@dataclass
class InjectorModifierConfig(ComponentConfig):
    resource_ids_to_inject: Tuple[bytes, ...]


class InjectorModifier(Modifier[InjectorModifierConfig]):
    targets = (MemoryRegion,)

    async def modify(self, resource: Resource, config: InjectorModifierConfig):
        if resource.has_tag(MemoryRegion):
            region = await resource.view_as(MemoryRegion)
        else:
            raise TypeError(f"Expected resource injected to be MemoryRegion")

        region_resource_data_id = region.resource.get_data_id()
        if region_resource_data_id is None:
            raise ValueError(f"Cannot modify a resource with data ID of None")

        data_patches = []

        target_memory_region = await resource.view_as(MemoryRegion)

        for r_id in config.resource_ids_to_inject:
            injectable_r = await self._resource_factory.create(
                resource.get_job_id(),
                r_id,
                resource.get_resource_context(),
                resource.get_resource_view_context(),
                resource.get_component_context(),
                resource.get_job_context(),
            )
            injectable = await injectable_r.view_as(MemoryRegion)

            injectable_data_offset_start = target_memory_region.get_offset_in_self(
                injectable.virtual_address
            )
            injectable_data_offset_end = injectable_data_offset_start + injectable.size
            data_patches.append(
                DataPatch(
                    Range(injectable_data_offset_start, injectable_data_offset_end),
                    region_resource_data_id,
                    await injectable_r.get_data(),
                )
            )

        await self._data_service.apply_patches(data_patches)


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
