from ofrak.core import *
from tempfile import TemporaryDirectory
import os


from ofrak_cached_disassembly.components.cached_disassembly import CachedAnalysisStore
from ofrak_cached_disassembly.components.cached_disassembly_unpacker import (
    CachedCodeRegionUnpacker,
    CachedComplexBlockUnpacker,
    CachedBasicBlockUnpacker,
    CachedCodeRegionModifier,
)
from ofrak_pyghidra.standalone.pyghidra_analysis import unpack


_GHIDRA_AUTO_LOADABLE_FORMATS = [Elf, Ihex, Pe]


@dataclass
class PyGhidraAutoLoadProject(ResourceView):
    pass


@dataclass
class PyGhidraProject(ResourceView):
    pass


class PyGhidraAnalysisIdentifier(Identifier):
    """
    Component to identify resources to analyze with Ghidra. If this component is discovered,
    it will tag all [Program][ofrak.core.program.Program]s as GhidraProjects
    """

    id = b"GhidraAnalysisIdentifier"
    targets = (Program,)

    async def identify(self, resource: Resource, config=None):
        for tag in _GHIDRA_AUTO_LOADABLE_FORMATS:
            if resource.has_tag(tag):
                resource.add_tag(PyGhidraAutoLoadProject)


@dataclass
class PyGhidraUnpackerConfig(ComponentConfig):
    unpack_complex_blocks: bool


class PyGhidraAnalysisStore(CachedAnalysisStore):
    pass


class CachedCodeRegionModifier(CachedCodeRegionModifier):
    pass


class PyGhidraAutoAnalyzer(Analyzer[None, PyGhidraProject]):
    id = b"PyGhidraAutoAnalyzer"

    targets = (PyGhidraAutoLoadProject,)
    outputs = (PyGhidraProject,)

    def __init__(
        self,
        resource_factory: ResourceFactory,
        data_service: DataServiceInterface,
        resource_service: ResourceServiceInterface,
        analysis_store: PyGhidraAnalysisStore,
    ):
        super().__init__(resource_factory, data_service, resource_service)
        self.analysis_store = analysis_store

    async def analyze(self, resource: Resource, config=None):
        with TemporaryDirectory() as tempdir:
            program_file = os.path.join(tempdir, "program")
            await resource.flush_data_to_disk(program_file)
            self.analysis_store.store_analysis(resource.get_id(), unpack(program_file, False))
            program_attributes = await resource.analyze(ProgramAttributes)
            self.analysis_store.store_program_attributes(resource.get_id(), program_attributes)
            return PyGhidraProject()


class PyGhidraCodeRegionUnpacker(CachedCodeRegionUnpacker):
    id = b"PyGhidraCodeRegionUnpacker"

    async def unpack(self, resource: Resource, config=None):
        program_r = await resource.get_only_ancestor(ResourceFilter.with_tags(Program))
        if not self.analysis_store.id_exists(program_r.get_id()):
            await program_r.run(PyGhidraAutoAnalyzer)
        return await super().unpack(resource, config)


class PyGhidraComplexBlockUnpacker(CachedComplexBlockUnpacker):
    id = b"PyGhidraComplexBlockUnpacker"


class PyGhidraBasicBlockUnpacker(CachedBasicBlockUnpacker):
    id = b"PyGhidraBasicBlockUnpacker"
