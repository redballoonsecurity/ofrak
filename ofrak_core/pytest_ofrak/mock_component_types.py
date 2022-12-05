from abc import ABC
from typing import Tuple

from ofrak import Analyzer, Unpacker, Resource


class MockAnalyzer(Analyzer[None, Tuple], ABC):
    def __init__(self):
        super().__init__(None, None, None)

    async def analyze(self, resource: Resource, config=None) -> Tuple:
        return ()


class MockUnpacker(Unpacker[None]):
    targets = ()
    children = ()

    def __init__(self):
        super().__init__(None, None, None, None)

    async def unpack(self, resource, config=None):
        pass
