from abc import ABC
from typing import Any, Optional, Tuple, Type

from ofrak import Analyzer, Unpacker, Resource
from ofrak.model.component_model import ComponentConfig
from ofrak.resource_view import ResourceView


class MockAnalyzer(Analyzer[None, Tuple], ABC):
    def __init__(self):
        super().__init__(None, None, None)

    async def analyze(self, resource: Resource, config: Optional[ComponentConfig] = None) -> Any:
        return ()


class MockUnpacker(Unpacker[None]):
    targets: Tuple[Type[ResourceView], ...] = ()
    children: Tuple[Type[ResourceView], ...] = ()

    def __init__(self):
        super().__init__(None, None, None, None)

    async def unpack(self, resource, config=None):
        pass


class MockRunnableUnpacker(Unpacker[None]):
    targets: Tuple[Type[ResourceView], ...] = ()
    children: Tuple[Type[ResourceView], ...] = ()

    async def unpack(self, resource, config=None):
        pass
