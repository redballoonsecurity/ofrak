from dataclasses import dataclass
from tempfile312 import mkdtemp
import os
from typing import Dict
from xml.etree import ElementTree

from ofrak.component.analyzer import Analyzer
from ofrak.core.architecture import ProgramAttributes
from ofrak.core.complex_block import ComplexBlock
from ofrak.core.decompilation import DecompilationAnalysis
from ofrak.core.memory_region import MemoryRegion
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
from ofrak_cached_disassembly.components.cached_disassembly import CachedAnalysisStore
from ofrak_cached_disassembly.components.cached_disassembly_unpacker import (
    CachedAnalysis,
    CachedCodeRegionUnpacker,
    CachedComplexBlockUnpacker,
    CachedBasicBlockUnpacker,
    CachedGhidraCodeRegionModifier,
    CachedDecompilationAnalyzer,
)
from ofrak_pyghidra.standalone.pyghidra_analysis import unpack, decompile_all_functions
from ofrak_type.error import NotFoundError


_GHIDRA_AUTO_LOADABLE_FORMATS = [Elf, Ihex, Pe]


@dataclass
class PyGhidraProject(CachedAnalysis):
    pass


class PyGhidraAnalysisIdentifier(Identifier):
    """
    Component to identify resources to analyze with Ghidra. If this component is discovered,
    it will tag all [Program][ofrak.core.program.Program]s as GhidraProjects
    """

    id = b"GhidraAnalysisIdentifier"
    targets = (Program, Ihex)

    async def identify(self, resource: Resource, config=None):
        resource.add_tag(PyGhidraProject)


@dataclass
class PyGhidraUnpackerConfig(ComponentConfig):
    unpack_complex_blocks: bool


class PyGhidraAnalysisStore(CachedAnalysisStore):
    pass


class CachedGhidraCodeRegionModifier(CachedGhidraCodeRegionModifier):
    """
    Modifies code regions while maintaining Ghidra analysis caching and context, preserving Ghidra's
    understanding of the code structure across modifications. This specialized modifier integrates
    with Ghidra's analysis database. Use when making modifications that need to maintain Ghidra
    analysis state, performing iterative modifications within Ghidra workflows, preserving analysis
    context across changes, or ensuring modifications are reflected in Ghidra's database. Important
    for maintaining analysis consistency in Ghidra-based workflows.
    """


@dataclass
class PyGhidraAutoAnalyzerConfig(ComponentConfig):
    decomp: bool
    language: str


class PyGhidraAutoAnalyzer(Analyzer[None, PyGhidraProject]):
    """
    Runs Ghidra's comprehensive automated analysis on binaries including disassembly, function
    boundary detection, control flow analysis, data type propagation, symbol discovery,
    cross-reference generation, and pattern matching. This is Ghidra's powerful automatic analysis
    engine that does the heavy lifting. Use for comprehensive initial analysis of unknown
    executables, automated function discovery in stripped binaries, control flow graph generation,
    or creating a foundation for further manual analysis. Normally runs automatically in
    Ghidra-based workflows.
    """

    id = b"PyGhidraAutoAnalyzer"

    targets = (PyGhidraProject,)
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
        tempdir = mkdtemp(prefix="rbs-pyghidra-bin")
        program_file = os.path.join(tempdir, "program")
        await resource.flush_data_to_disk(program_file)
        if config is None:
            decomp = False
            language = None
        else:
            decomp = config.decomp
            language = config.language
        for tag in _GHIDRA_AUTO_LOADABLE_FORMATS:
            if resource.has_tag(tag):
                self.analysis_store.store_analysis(
                    resource.get_id(), unpack(program_file, decomp, language)
                )
                return PyGhidraProject()

        program_attrs = resource.get_attributes(ProgramAttributes)
        # Guess that the base address is the min start address of any memory region
        regions = await resource.get_children_as_view(
            MemoryRegion, r_filter=ResourceFilter.with_tags(MemoryRegion)
        )
        base_address = min(code_region.virtual_address for code_region in regions)

        self.analysis_store.store_analysis(
            resource.get_id(),
            unpack(
                program_file,
                decomp,
                language=_arch_info_to_processor_id(program_attrs),
                base_address=base_address,
            ),
        )
        return PyGhidraProject()


@dataclass
class PyGhidraCodeRegionUnpackerConfig(ComponentConfig):
    decomp: bool
    language: str


class PyGhidraCodeRegionUnpacker(CachedCodeRegionUnpacker):
    """
    Uses Ghidra's analysis engine to automatically disassemble code regions and identify function
    boundaries (complex blocks). Ghidra analyzes control flow, recognizes function
    prologues/epilogues, and determines where functions start and end. Use when you need automated
    function discovery in executable code, especially for binaries without symbols.
    """

    id = b"PyGhidraCodeRegionUnpacker"

    async def unpack(self, resource: Resource, config: PyGhidraCodeRegionUnpackerConfig = None):
        program_r = await resource.get_only_ancestor(ResourceFilter.with_tags(PyGhidraProject))
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
    """
    Uses Ghidra to disassemble complete functions (complex blocks) into their constituent basic
    blocks and data words. Basic blocks are sequences of instructions with a single entry point and
    single exit point, representing straight-line code between branches. Use when performing control
    flow analysis to understand branching, loops, and function structure. This enables detailed
    analysis of how code flows through a function.
    """

    id = b"PyGhidraComplexBlockUnpacker"


class PyGhidraBasicBlockUnpacker(CachedBasicBlockUnpacker):
    """
    Uses Ghidra to disassemble basic blocks into individual assembly instructions, providing the
    finest-grained view of executable code. Each instruction is extracted with its mnemonic,
    operands, and address. Use when you need instruction-level analysis, want to examine specific
    assembly operations, or are preparing for instruction-level modifications. This is the deepest
    level of code structure extraction.
    """

    id = b"PyGhidraBasicBlockUnpacker"


class PyGhidraDecompilationAnalyzer(CachedDecompilationAnalyzer):
    """
    Uses Ghidra's decompiler to convert assembly instructions back into pseudo-C source code,
    applying data type inference, control flow reconstruction, variable naming, and structural
    analysis to produce high-level code representations. Use when you need high-level understanding
    of function behavior, want to analyze complex logic or algorithms, prepare for function
    reimplementation, or need to understand code quickly. The decompiled code should be verified
    against disassembly.
    """

    id = b"PyGhidraDecompilationAnalyzer"

    targets = (ComplexBlock,)
    outputs = (DecompilationAnalysis,)

    async def analyze(self, resource: Resource, config=None):
        program_r = await resource.get_only_ancestor(ResourceFilter.with_tags(PyGhidraProject))
        if self.analysis_store.id_exists(program_r.get_id()):
            complex_block = await resource.view_as(ComplexBlock)
            cb_key = f"func_{complex_block.virtual_address}"
            analysis = self.analysis_store.get_analysis(program_r.get_id())
            if "decompilation" not in analysis[cb_key]:
                program_file = analysis["metadata"]["path"]
                for cb_key, decomp in decompile_all_functions(program_file, None).items():
                    analysis[cb_key]["decompilation"] = decomp
                self.analysis_store.store_analysis(program_r.get_id(), analysis)
        else:
            tempdir = mkdtemp(prefix="rbs-pyghidra-bin")
            program_file = os.path.join(tempdir, "program")
            await program_r.flush_data_to_disk(program_file)
            try:
                program_attrs = program_r.get_attributes(ProgramAttributes)
            except NotFoundError:
                program_attrs = await program_r.analyze(ProgramAttributes)
            analysis = unpack(
                program_file, True, language=_arch_info_to_processor_id(program_attrs)
            )
            self.analysis_store.store_analysis(program_r.get_id(), analysis)

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
    default_proc_id = f"{partial_proc_id}:default"

    ghidra_install_dir = os.environ.get("GHIDRA_INSTALL_DIR")
    if not ghidra_install_dir:
        raise ValueError("GHIDRA_INSTALL_DIR environment variable must be set")
    ldefs = os.path.join(ghidra_install_dir, "Ghidra", "Processors", family, "data", "languages")
    processors_rejected = set()
    default_proc_id_found = False
    for file in os.listdir(ldefs):
        if not file.endswith(".ldefs"):
            continue

        tree = ElementTree.parse(os.path.join(ldefs, file))
        for language in tree.getroot().iter(tag="language"):
            proc_id = language.attrib["id"]
            # Ghidra has a list of alternative names for each support language spec
            # This is useful and interesting, for example it has the IDA equivalent name
            if not proc_id.startswith(partial_proc_id):
                # Don't even consider language if it doesn't match ISA, bitwidth, endianness
                continue
            if proc_id == default_proc_id:
                default_proc_id_found = True
                if not processor.sub_isa and not processor.processor:
                    # default_proc_id found, and the ArchoInfo doesn't contain any info to narrow it down further, so just break early to return the default
                    break
            names = [
                name_elem.attrib["name"].lower() for name_elem in language.iter(tag="external_name")
            ]
            names.append(proc_id.split(":")[-1])
            for name in names:
                if not processor.sub_isa and not processor.processor:
                    if name.endswith("_any"):
                        return proc_id

                if processor.sub_isa and processor.sub_isa.value.lower() == name:
                    return proc_id

                if processor.processor and processor.processor.value.lower() == name:
                    return proc_id

                #  Jank but necessary, for instance the last part of the language ID for ARMv8A is v8A, but the processor ID is armv8-a
                if processor.sub_isa and all(
                    char in processor.sub_isa.value.lower() for char in name.lower()
                ):
                    return proc_id

                if processor.processor and all(
                    char in processor.processor.value.lower() for char in name.lower()
                ):
                    return proc_id
            processors_rejected.add(proc_id)

    if default_proc_id_found:
        return default_proc_id

    if len(processors_rejected) == 1:
        return processors_rejected.pop()

    raise Exception(
        f"Could not determine a Ghidra language spec for the given architecture info "
        f"{processor}. Considered the following specs:\n{', '.join(processors_rejected)}"
    )
