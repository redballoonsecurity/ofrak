from dataclasses import dataclass
import json
from tempfile import TemporaryDirectory
import os
from typing import Dict

from ofrak.component.analyzer import Analyzer
from ofrak.service.data_service_i import DataServiceInterface
from ofrak.service.resource_service_i import ResourceFilter, ResourceServiceInterface
from ofrak_type import ArchInfo, Endianness, InstructionSet


from ofrak.component.identifier import Identifier
from ofrak.core.elf.model import Elf
from ofrak.core.ihex import Ihex
from ofrak.core.pe.model import Pe
from ofrak.core.program import Program
from ofrak.model.component_model import ComponentConfig
from ofrak.resource import Resource, ResourceFactory
from ofrak.resource_view import ResourceView
from ofrak_cached_disassembly.components.cached_disassembly import CachedAnalysisStore
from ofrak_cached_disassembly.components.cached_disassembly_unpacker import (
    CachedCodeRegionUnpacker,
    CachedComplexBlockUnpacker,
    CachedBasicBlockUnpacker,
    CachedCodeRegionModifier,
    CachedDecompilationAnalyzer,
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
    targets = (Program, Ihex)

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


@dataclass
class PyGhidraAutoAnalyzerConfig(ComponentConfig):
    decomp: bool
    language: str


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

    async def analyze(self, resource: Resource, config: PyGhidraAutoAnalyzerConfig = None):
        with TemporaryDirectory() as tempdir:
            program_file = os.path.join(tempdir, "program")
            await resource.flush_data_to_disk(program_file)
            if config is not None:
                analysis = unpack(program_file, config.decomp, config.language)
                with open("/root/analysis.json", "w") as fh:
                    json.dump(analysis, fh)
                self.analysis_store.store_analysis(
                    resource.get_id(),
                    analysis,
                )
            else:
                self.analysis_store.store_analysis(
                    resource.get_id(), unpack(program_file, False, None)
                )
            # program_attributes = await resource.analyze(ProgramAttributes)
            # self.analysis_store.store_program_attributes(resource.get_id(), program_attributes)
            return PyGhidraProject()


@dataclass
class PyGhidraCodeRegionUnpackerConfig(ComponentConfig):
    decomp: bool
    language: str


class PyGhidraCodeRegionUnpacker(CachedCodeRegionUnpacker):
    id = b"PyGhidraCodeRegionUnpacker"

    async def unpack(self, resource: Resource, config: PyGhidraCodeRegionUnpackerConfig = None):
        program_r = await resource.get_only_ancestor(
            ResourceFilter.with_tags(PyGhidraAutoLoadProject)
        )
        if not self.analysis_store.id_exists(program_r.get_id()):
            if config is not None:
                await program_r.run(
                    PyGhidraAutoAnalyzer,
                    config=PyGhidraAutoAnalyzerConfig(
                        decomp=config.decomp, language=config.language
                    ),
                )
            else:
                await program_r.run(PyGhidraAutoAnalyzer)
        return await super().unpack(resource, config)


class PyGhidraComplexBlockUnpacker(CachedComplexBlockUnpacker):
    id = b"PyGhidraComplexBlockUnpacker"


class PyGhidraBasicBlockUnpacker(CachedBasicBlockUnpacker):
    id = b"PyGhidraBasicBlockUnpacker"


class PyGhidraDecompilationAnalyzer(CachedDecompilationAnalyzer):
    id = b"PyGhidraDecompilationAnalyzer"

    async def analyze(self, resource: Resource, config=None):
        program_r = await resource.get_only_ancestor(
            ResourceFilter.with_tags(PyGhidraAutoLoadProject)
        )
        if not self.analysis_store.get_analysis(program_r.get_id())["metadata"]["decompiled"]:
            with TemporaryDirectory() as tempdir:
                program_file = os.path.join(tempdir, "program")
                await program_r.flush_data_to_disk(program_file)

                self.analysis_store.store_analysis(program_r.get_id(), unpack(program_file, True))
        return await super().analyze(resource, config)


def _arch_info_to_processor_id(processor: ArchInfo):
    families: Dict[InstructionSet, str] = {
        InstructionSet.ARM: "ARM",
        InstructionSet.AARCH64: "AARCH64",
        InstructionSet.MIPS: "MIPS",
        InstructionSet.PPC: "PowerPC",
        InstructionSet.M68K: "68000",
        InstructionSet.X86: "x86",
    }
    family = families.get(processor.isa)

    endian = "BE" if processor.endianness is Endianness.BIG_ENDIAN else "LE"
    # Ghidra proc IDs are of the form "ISA:endianness:bitWidth:suffix", where the suffix can indicate a specific processor or sub-ISA
    # The goal of the follow code is to identify the best proc ID for the ArchInfo, and we expect to be able to fall back on this default
    partial_proc_id = f"{family}:{endian}:{processor.bit_width.value}"
    # TODO: There are also some proc_ids that end with '_any' which are default-like
    if family == "ARM":
        default_proc_id = f"{partial_proc_id}:Cortex"
    else:
        default_proc_id = f"{partial_proc_id}:default"
    return default_proc_id
