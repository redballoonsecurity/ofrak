import asyncio
import tempfile
from concurrent.futures.process import ProcessPoolExecutor
from dataclasses import dataclass
from typing import Dict

from ofrak.resource import ResourceFactory, Resource

from ofrak.model.resource_model import ResourceAttributes

from ofrak.component.abstract import ComponentMissingDependencyError
from ofrak.component.analyzer import Analyzer

try:
    import binwalk

    BINWALK_INSTALLED = True
except ImportError:
    BINWALK_INSTALLED = False

from ofrak.core.binary import GenericBinary
from ofrak.core.filesystem import File
from ofrak.model.component_model import ComponentExternalTool
from ofrak.service.data_service_i import DataServiceInterface
from ofrak.service.resource_service_i import ResourceServiceInterface


class _BinwalkExternalTool(ComponentExternalTool):
    def __init__(self):
        super().__init__(
            "binwalk",
            "https://github.com/ReFirmLabs/binwalk",
            install_check_arg="",
        )

    def is_tool_installed(self) -> bool:
        return BINWALK_INSTALLED


BINWALK_TOOL = _BinwalkExternalTool()


@dataclass(**ResourceAttributes.DATACLASS_PARAMS)
class BinwalkAttributes(ResourceAttributes):
    offsets: Dict[int, str]


class BinwalkAnalyzer(Analyzer[None, BinwalkAttributes]):
    targets = (GenericBinary, File)
    outputs = (BinwalkAttributes,)
    external_dependencies = (BINWALK_TOOL,)

    def __init__(
        self,
        resource_factory: ResourceFactory,
        data_service: DataServiceInterface,
        resource_service: ResourceServiceInterface,
    ):
        super().__init__(resource_factory, data_service, resource_service)
        self.pool = ProcessPoolExecutor()

    async def analyze(self, resource: Resource, config=None) -> BinwalkAttributes:
        if not BINWALK_INSTALLED:
            raise ComponentMissingDependencyError(self, BINWALK_TOOL)
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
