from dataclasses import dataclass

from ofrak.component.modifier import Modifier
from ofrak.model.component_model import ComponentConfig
from ofrak.resource import Resource
from ofrak_type.range import Range


@dataclass
class RawReplaceConfig(ComponentConfig):
    content: bytes
    offset: int
    size: int


@dataclass
class RawExtendConfig(ComponentConfig):
    content: bytes


class RawReplaceModifier(Modifier[RawReplaceConfig]):
    """
    Replace a binary with new data
    """

    targets = ()

    async def modify(self, resource: Resource, config: RawReplaceConfig):
        resource.queue_patch(Range(config.offset, config.offset + config.size), config.content)


class RawExtendModifier(Modifier[RawExtendConfig]):
    """
    Extend a binary with new data.
    """

    targets = ()

    async def modify(self, resource: Resource, config: RawExtendConfig):
        if len(config.content) == 0:
            raise ValueError("Content of the extended space not provided")
        data = await resource.get_data()
        data += config.content
        resource.queue_patch(Range(0, await resource.get_data_length()), data)
