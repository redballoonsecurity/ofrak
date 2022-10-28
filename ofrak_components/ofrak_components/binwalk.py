import asyncio
import tempfile
from concurrent.futures.process import ProcessPoolExecutor
from dataclasses import dataclass
from typing import Dict

import binwalk

from ofrak import Analyzer, Resource, ResourceFactory, ResourceAttributes
from ofrak.core import GenericBinary, File
from ofrak.service.data_service_i import DataServiceInterface
from ofrak.service.resource_service_i import ResourceServiceInterface


@dataclass(**ResourceAttributes.DATACLASS_PARAMS)
class BinwalkAttributes(ResourceAttributes):
    offsets: Dict[int, str]


class BinwalkAnalyzer(Analyzer[None, BinwalkAttributes]):
    targets = (GenericBinary, File)
    outputs = (BinwalkAttributes,)

    def __init__(
        self,
        resource_factory: ResourceFactory,
        data_service: DataServiceInterface,
        resource_service: ResourceServiceInterface,
    ):
        super().__init__(resource_factory, data_service, resource_service)
        self.pool = ProcessPoolExecutor()

    async def analyze(self, resource: Resource, config=None) -> BinwalkAttributes:
        with tempfile.NamedTemporaryFile() as temp_file:
            data = await resource.get_data()
            temp_file.write(data)
            temp_file.flush()

            # Should errors be handled the way they are in the `DataSummaryAnalyzer`? Likely to be
            # overkill here.
            offsets = await asyncio.get_running_loop().run_in_executor(
                self.pool, _run_binwalk_on_file, temp_file.name
            )
        return BinwalkAttributes(offsets)


def _run_binwalk_on_file(filename):  # pragma: no cover
    offsets = dict()
    for module in binwalk.scan(filename, signature=True):
        for result in module.results:
            offsets[result.offset] = result.description
    return offsets
