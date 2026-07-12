import logging
import os
import threading
import time
from dataclasses import dataclass
from typing import Dict, Optional, Tuple, Union, List, Any, Callable
from xml.etree import ElementTree

import pyghidra

from ofrak import Modifier
from ofrak.component.analyzer import Analyzer
from ofrak.component.identifier import Identifier
from ofrak.core import (
    CodeRegion,
    CodeRegionUnpacker,
    BasicBlock,
    DataWord,
    BasicBlockUnpacker,
    Instruction,
)
from ofrak.core.architecture import ProgramAttributes
from ofrak.core.complex_block import ComplexBlock, ComplexBlockUnpacker
from ofrak.core.decompilation import DecompilationAnalysis, DecompilationAnalyzer
from ofrak.core.elf.model import Elf, ElfHeader, ElfType
from ofrak.core.ihex import Ihex
from ofrak.core.memory_region import MemoryRegion
from ofrak.core.pe.model import Pe
from ofrak.core.program import Program
from ofrak.model.component_model import ComponentConfig
from ofrak.resource import Resource, ResourceFactory
from ofrak.resource_view import ResourceView
from ofrak.service.abstract_ofrak_service import AbstractOfrakService
from ofrak.service.component_locator_i import ComponentLocatorInterface
from ofrak.service.data_service_i import DataServiceInterface
from ofrak.service.resource_service_i import ResourceFilter, ResourceServiceInterface
from ofrak_pyghidra.standalone.pyghidra_analysis import _unpack_program, _unpack_code_region
from ofrak_pyghidra.standalone.pyghidra_analysis import (
    prepare_project,
    _unpack_complex_block,
    _unpack_basic_block,
)
from ofrak_type import ArchInfo, Endianness, InstructionSet, InstructionSetMode
from ofrak_type.error import NotFoundError

_GHIDRA_AUTO_LOADABLE_FORMATS = [Elf, Ihex, Pe]

LOGGER = logging.getLogger("ofrak_pyghidra")


@dataclass
class PyGhidraProject(ResourceView):
    """
    A resource which may be loaded into PyGhidra and analyzed.
    """


@dataclass
class PyGhidraAutoLoadProject(PyGhidraProject):
    """
    A resource which PyGhidra can automatically load with one of its existing Loaders (e.g. ELF).
    """


@dataclass
class PyGhidraCustomLoadProject(PyGhidraProject):
    """
    A resource which PyGhidra does not have an existing loader for and cannot load automatically.
    Before analysis, we need to inform PyGhidra of correct processor and segments.
    """


class PyGhidraAnalysisIdentifier(Identifier):
    """
    Tags Program resources for PyGhidra analysis. Auto-loadable formats (ELF, PE, Ihex) get PyGhidraAutoLoadProject tag,
    others get PyGhidraCustomLoadProject. Enables PyGhidra-based components to run on the resource.
    """

    id = b"PyGhidraAnalysisIdentifier"
    targets = (Program,)

    async def identify(self, resource: Resource, config=None):
        for tag in _GHIDRA_AUTO_LOADABLE_FORMATS:
            if resource.has_tag(tag):
                resource.add_tag(PyGhidraAutoLoadProject)
                return

        resource.add_tag(PyGhidraCustomLoadProject)


@dataclass
class PyGhidraUnpackerConfig(ComponentConfig):
    unpack_complex_blocks: bool


class PyGhidraAnalysisStore(AbstractOfrakService):
    """
    Manages open Ghidra project handles, keyed by a content-derived cache_key
    (MD5 of binary + language + base_address + memory_regions).  Multiple OFRAK
    resource IDs can share the same Ghidra project / JVM context; the project is
    only closed when its last resource detaches.
    """

    def __init__(self):
        super().__init__()
        self._lock = threading.Lock()

        # cache_key -> (flat_api, ctx)
        self._projects: Dict[str, Tuple] = {}
        # cache_key -> set of resource_ids currently using this project
        self._project_refs: Dict[str, set] = {}

        # resource_id -> cache_key
        self._resource_to_project: Dict[bytes, str] = {}

        self._base_address: Dict[str, int] = {}

    # ------------------------------------------------------------------
    # Lookups
    # ------------------------------------------------------------------

    def get_flat_api(self, resource_id: bytes):
        """Return the cached flat_api for a resource, or None."""
        with self._lock:
            cache_key = self._resource_to_project.get(resource_id)
            if cache_key is None:
                return None
            entry = self._projects.get(cache_key)
            return entry[0] if entry is not None else None

    def set_base_address(self, _id: bytes, address: int):
        with self._lock:
            cache_key = self._resource_to_project.get(_id)
        if cache_key is not None:
            self._base_address[cache_key] = address

    def get_base_address(self, _id: bytes) -> Optional[int]:
        with self._lock:
            cache_key = self._resource_to_project.get(_id)
        if cache_key is None:
            return None
        return self._base_address.get(cache_key)

    # ------------------------------------------------------------------
    # Project lifecycle
    # ------------------------------------------------------------------

    async def create_project(
        self,
        resource: Resource,
        language: Optional[str] = None,
        base_address: Union[str, int, None] = None,
        memory_regions: Optional[List[Dict[str, Any]]] = None,
        post_analysis_script: Optional[Callable] = None,
    ) -> Tuple:
        project_params = await prepare_project(resource, language, base_address, memory_regions)

        cache_key = project_params["cache_key"]
        program_file = project_params["program_file"]
        cache_dir = project_params["project_location"]
        project_name = project_params["project_name"]
        cached = project_params["cached"]
        resource_id = resource.get_id()

        with self._lock:
            if cache_key in self._projects:
                self._project_refs[cache_key].add(resource_id)
                self._resource_to_project[resource_id] = cache_key
                flat_api = self._projects[cache_key][0]
                LOGGER.warning(
                    "Reusing already-open Ghidra project for resource %s (cache_key=%s, refs=%d)",
                    resource_id.hex(),
                    cache_key[:12],
                    len(self._project_refs[cache_key]),
                )
                return flat_api

        open_start = time.time()
        if cached:
            LOGGER.warning("Cache HIT: reusing Ghidra project on disk")
        else:
            LOGGER.warning("Cache MISS: creating new Ghidra project")
        ctx = pyghidra.open_program(
            program_file,
            language=language,
            project_location=cache_dir,
            project_name=project_name,
            analyze=not cached,
        )
        flat_api = ctx.__enter__()
        open_elapsed = time.time() - open_start
        LOGGER.warning(f"Ghidra project opened in {open_elapsed:.1f}s")

        if not cached:
            from ghidra.util.task import TaskMonitor
            from java.io import ByteArrayInputStream

            if memory_regions:
                program = flat_api.getCurrentProgram()
                memory = program.getMemory()
                address_factory = program.getAddressFactory()
                default_space = address_factory.getDefaultAddressSpace()

                for block in memory.getBlocks():
                    memory.removeBlock(block, TaskMonitor.DUMMY)

                for region in memory_regions:
                    addr = default_space.getAddress(region["virtual_address"])
                    data_bytes = region["data"]
                    block_name = f"region_{region['virtual_address']:x}"

                    try:
                        input_stream = ByteArrayInputStream(data_bytes)

                        memory.createInitializedBlock(
                            block_name,
                            addr,
                            input_stream,
                            len(data_bytes),
                            TaskMonitor.DUMMY,
                            False,
                        )

                        block = memory.getBlock(addr)
                        block.setExecute(True)
                        block.setRead(True)
                    except Exception as e:
                        logging.warning(
                            f"Failed to create memory block at "
                            f"0x{region['virtual_address']:x}: {e}"
                        )
                flat_api.analyzeAll(program)

            if base_address:
                if isinstance(base_address, str):
                    if base_address.startswith("0x"):
                        base_address = int(base_address, 16)
                    else:
                        base_address = int(base_address)

                program = flat_api.getCurrentProgram()
                address_factory = program.getAddressFactory()
                new_base_addr = address_factory.getDefaultAddressSpace().getAddress(
                    hex(base_address)
                )
                program.setImageBase(new_base_addr, True)
                LOGGER.info(f"Rebased program address to {hex(base_address)}")

            if post_analysis_script:
                post_analysis_script(flat_api)

            LOGGER.warning("Flushing Ghidra project to reload")
            ctx.__exit__(None, None, None)
            ctx = pyghidra.open_program(
                program_file,
                language=language,
                project_location=cache_dir,
                project_name=project_name,
                analyze=False,
            )
            flat_api = ctx.__enter__()
            LOGGER.warning("Reloaded Ghidra project")

        with self._lock:
            self._projects[cache_key] = (flat_api, ctx)
            self._project_refs.setdefault(cache_key, set()).add(resource_id)
            self._resource_to_project[resource_id] = cache_key

        return flat_api

    def close_program(self, resource_id: bytes):
        """Detach a resource from its project.  Closes the project only when
        the last resource using it detaches."""
        with self._lock:
            cache_key = self._resource_to_project.pop(resource_id, None)
            if cache_key is None:
                return
            refs = self._project_refs.get(cache_key)
            if refs is not None:
                refs.discard(resource_id)
            if refs is not None and len(refs) > 0:
                LOGGER.warning(
                    "Resource %s detached from project %s (%d refs remain)",
                    resource_id.hex(),
                    cache_key[:12],
                    len(refs),
                )
                return
            self._project_refs.pop(cache_key, None)
            entry = self._projects.pop(cache_key, None)
            self._base_address.pop(cache_key, None)

        if entry is not None:
            _, ctx = entry
            try:
                ctx.__exit__(None, None, None)
            except Exception as e:
                LOGGER.warning(e)

    def close_all(self):
        """Close all open project handles."""
        for rid in list(self._resource_to_project.keys()):
            self.close_program(rid)

    async def shutdown(self):
        LOGGER.warning("SHUTTING DOWN NOW!")
        return self.close_all()

    def __del__(self):  # pragma: no cover
        self.close_all()


class PyGhidraCodeRegionModifier(Modifier[None]):
    """
    Modifies code regions while maintaining Ghidra analysis caching and context, preserving Ghidra's
    understanding of the code structure across modifications. This specialized modifier integrates
    with Ghidra's analysis database. Use when making modifications that need to maintain Ghidra
    analysis state, performing iterative modifications within Ghidra workflows, preserving analysis
    context across changes, or ensuring modifications are reflected in Ghidra's database. Important
    for maintaining analysis consistency in Ghidra-based workflows.
    """

    targets = (CodeRegion,)

    def __init__(
        self,
        resource_factory: ResourceFactory,
        data_service: DataServiceInterface,
        resource_service: ResourceServiceInterface,
        analysis_store: PyGhidraAnalysisStore,
    ):
        super().__init__(resource_factory, data_service, resource_service)
        self.analysis_store = analysis_store

    async def modify(self, resource: Resource, config: None):
        program_r = await resource.get_only_ancestor(ResourceFilter.with_tags(PyGhidraProject))
        flat_api = self.analysis_store.get_flat_api(program_r.get_id())
        if flat_api is None:
            raise ValueError("Something is off")
        ofrak_code_regions = await program_r.get_descendants_as_view(
            v_type=CodeRegion, r_filter=ResourceFilter(tags=[CodeRegion])
        )

        ghidra_code_regions = _unpack_program(flat_api)
        filtered_code_region = [
            CodeRegion(virtual_address=mem_region["virtual_address"], size=mem_region["size"])
            for mem_region in ghidra_code_regions
            if mem_region["executable"]
        ]

        ofrak_code_regions = sorted(ofrak_code_regions, key=lambda cr: cr.virtual_address)
        backend_code_regions = sorted(filtered_code_region, key=lambda cr: cr.virtual_address)

        # We only want to adjust the address of a CodeRegion if the original binary is position-independent.
        # Implement PIE-detection for other file types as necessary.
        if program_r.has_tag(Elf):
            elf_header = await program_r.get_only_descendant_as_view(
                ElfHeader, r_filter=ResourceFilter(tags=[ElfHeader])
            )
            if elf_header is not None and elf_header.e_type == ElfType.ET_DYN.value:
                code_region = await resource.view_as(CodeRegion)
                base_addr = self.analysis_store.get_base_address(program_r.get_id())
                if base_addr:
                    new_cr = CodeRegion(
                        code_region.virtual_address + base_addr,
                        code_region.size,
                    )
                    code_region.resource.add_view(new_cr)
                elif len(ofrak_code_regions) > 0:
                    relative_va = (
                        code_region.virtual_address - ofrak_code_regions[0].virtual_address
                    )

                    for backend_cr in backend_code_regions:
                        backend_relative_va = (
                            backend_cr.virtual_address - backend_code_regions[0].virtual_address
                        )
                        if (
                            backend_relative_va == relative_va
                            and backend_cr.size == code_region.size
                        ):
                            code_region.resource.add_view(backend_cr)
                            self.analysis_store.set_base_address(
                                program_r.get_id(),
                                backend_cr.virtual_address - code_region.virtual_address,
                            )
                await resource.save()


@dataclass
class PyGhidraAnalyzerConfig(ComponentConfig):
    decomp: bool
    language: str


class PyGhidraAutoAnalyzer(Analyzer[None, PyGhidraAutoLoadProject]):
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

    targets = (PyGhidraAutoLoadProject,)
    outputs = (PyGhidraAutoLoadProject,)

    def __init__(
        self,
        resource_factory: ResourceFactory,
        data_service: DataServiceInterface,
        resource_service: ResourceServiceInterface,
        analysis_store: PyGhidraAnalysisStore,
    ):
        super().__init__(resource_factory, data_service, resource_service)
        self.analysis_store = analysis_store

    def post_analysis_script(self, flat_api) -> None:
        """Override in subclasses to run custom Ghidra code after analysis."""

    async def analyze(self, resource: Resource, config: PyGhidraAnalyzerConfig = None):
        if not self.analysis_store.get_flat_api(resource.get_id()):
            await resource.identify()  # Creates tags
            try:
                program_attrs = resource.get_attributes(ProgramAttributes)
                language = _arch_info_to_processor_id(program_attrs)
            except NotFoundError:
                language = None
            if config is None:
                decomp = False
            else:
                decomp = config.decomp
                language = config.language

            base_address = None
            for tag in _GHIDRA_AUTO_LOADABLE_FORMATS:
                if resource.has_tag(tag):
                    break
            else:
                program_attrs = resource.get_attributes(ProgramAttributes)
                language = _arch_info_to_processor_id(program_attrs)
                regions = await resource.get_children_as_view(
                    MemoryRegion, r_filter=ResourceFilter.with_tags(MemoryRegion)
                )
                base_address = min(code_region.virtual_address for code_region in regions)

            await self.analysis_store.create_project(
                resource,
                language,
                base_address=base_address,
                post_analysis_script=self.post_analysis_script,
            )
        return PyGhidraAutoLoadProject()


class PyGhidraCustomLoadAnalyzer(Analyzer[None, PyGhidraCustomLoadProject]):
    """
    Runs Ghidra's automated analysis on binaries with custom memory region setup. This analyzer
    explicitly creates all memory regions from the OFRAK Program's MemoryRegion children in Ghidra
    before running analysis. Use when analyzing raw firmware or binaries with non-standard memory
    layouts that Ghidra doesn't automatically detect. This ensures all memory regions are properly
    created and analyzed, which is critical for firmware with multiple discontinuous memory segments.
    """

    id = b"PyGhidraCustomLoadAnalyzer"

    targets = (PyGhidraCustomLoadProject,)
    outputs = (PyGhidraCustomLoadProject,)

    def __init__(
        self,
        resource_factory: ResourceFactory,
        data_service: DataServiceInterface,
        resource_service: ResourceServiceInterface,
        analysis_store: PyGhidraAnalysisStore,
    ):
        super().__init__(resource_factory, data_service, resource_service)
        self.analysis_store = analysis_store

    def post_analysis_script(self, flat_api) -> None:
        """Override in subclasses to run custom Ghidra code after analysis."""

    async def analyze(self, resource: Resource, config: PyGhidraAnalyzerConfig):
        if not self.analysis_store.get_flat_api(resource.get_id()):
            if config is None:
                try:
                    program_attrs = resource.get_attributes(ProgramAttributes)
                    language = _arch_info_to_processor_id(program_attrs)
                except NotFoundError:
                    language = None
                decomp = False
            else:
                decomp = config.decomp
                language = config.language

            # Prepare memory regions data
            regions = await resource.get_children_as_view(
                MemoryRegion, r_filter=ResourceFilter.with_tags(MemoryRegion)
            )

            memory_regions = []
            for region in regions:
                region_data = await region.resource.get_data()
                memory_regions.append(
                    {
                        "virtual_address": region.virtual_address,
                        "size": region.size,
                        "data": region_data,
                    }
                )

            await self.analysis_store.create_project(
                resource,
                language,
                memory_regions=memory_regions,
                post_analysis_script=self.post_analysis_script,
            )
        return PyGhidraCustomLoadProject()


@dataclass
class PyGhidraCodeRegionUnpackerConfig(ComponentConfig):
    decomp: bool
    language: str


class PyGhidraCodeRegionUnpacker(CodeRegionUnpacker):
    """
    Uses Ghidra's analysis engine to automatically disassemble code regions and identify function
    boundaries (complex blocks). Ghidra analyzes control flow, recognizes function
    prologues/epilogues, and determines where functions start and end. Use when you need automated
    function discovery in executable code, especially for binaries without symbols.
    """

    id = b"PyGhidraCodeRegionUnpacker"

    def __init__(
        self,
        resource_factory: ResourceFactory,
        data_service: DataServiceInterface,
        resource_service: ResourceServiceInterface,
        analysis_store: PyGhidraAnalysisStore,
        component_locator: ComponentLocatorInterface,
    ):
        super().__init__(resource_factory, data_service, resource_service, component_locator)
        self.analysis_store = analysis_store

    async def unpack(self, resource: Resource, config: PyGhidraCodeRegionUnpackerConfig = None):
        flat_api = await self._get_or_create_flat_api(config, resource)
        open_start = time.time()
        code_region_view = await resource.view_as(CodeRegion)

        await resource.run(PyGhidraCodeRegionModifier)
        code_regions = _unpack_program(flat_api)
        target_region = None
        for cr in code_regions:
            if cr["virtual_address"] == code_region_view.virtual_address:
                target_region = cr
                break
        if target_region is None:
            LOGGER.warning(
                f"No Ghidra code region found matching virtual address "
                f"0x{code_region_view.virtual_address:x}"
            )
            return

        func_cbs = _unpack_code_region(target_region, flat_api)
        for _func, complex_block in func_cbs:
            cb = ComplexBlock(
                virtual_address=complex_block["virtual_address"],
                size=complex_block["size"],
                name=complex_block["name"],
            )
            await code_region_view.create_child_region(cb)

        LOGGER.warning(f"Pyghidra Analysis time: {time.time() - open_start:.1f}s")

    async def _get_or_create_flat_api(self, config, resource):
        program_r = await resource.get_only_ancestor(ResourceFilter.with_tags(Program))
        await program_r.identify()  # Enusre PyGhidra Project tags are applied
        flat_api = self.analysis_store.get_flat_api(program_r.get_id())
        if not flat_api:
            if config is not None:
                analyzer_config = PyGhidraAnalyzerConfig(
                    decomp=config.decomp, language=config.language
                )
            else:
                analyzer_config = None
            if program_r.has_tag(PyGhidraAutoLoadProject):
                await program_r.run(
                    PyGhidraAutoAnalyzer,
                    config=analyzer_config,
                )
            elif program_r.has_tag(PyGhidraCustomLoadProject):
                await program_r.run(
                    PyGhidraCustomLoadAnalyzer,
                    config=analyzer_config,
                )
            else:
                raise ValueError(
                    f"resource {resource} does not have any tag that allow analysis with the PyGhidra backend."
                )
            flat_api = self.analysis_store.get_flat_api(program_r.get_id())
            if flat_api is None:
                raise ValueError("Something went terribly wrong")
        return flat_api


class PyGhidraComplexBlockUnpacker(ComplexBlockUnpacker):
    """
    Uses Ghidra to disassemble complete functions (complex blocks) into their constituent basic
    blocks and data words. Basic blocks are sequences of instructions with a single entry point and
    single exit point, representing straight-line code between branches. Use when performing control
    flow analysis to understand branching, loops, and function structure. This enables detailed
    analysis of how code flows through a function.
    """

    id = b"PyGhidraComplexBlockUnpacker"

    def __init__(
        self,
        resource_factory: ResourceFactory,
        data_service: DataServiceInterface,
        resource_service: ResourceServiceInterface,
        analysis_store: PyGhidraAnalysisStore,
        component_locator: ComponentLocatorInterface,
    ):
        super().__init__(resource_factory, data_service, resource_service, component_locator)
        self.analysis_store = analysis_store

    async def unpack(self, resource: Resource, config=None):
        program_r = await resource.get_only_ancestor(ResourceFilter.with_tags(PyGhidraProject))
        program_attributes = await program_r.analyze(ProgramAttributes)
        flat_api = self.analysis_store.get_flat_api(program_r.get_id())
        from ghidra.program.model.block import BasicBlockModel
        from java.math import BigInteger

        complex_block = await resource.view_as(ComplexBlock)
        program = flat_api.getCurrentProgram()
        addr = (
            program.getAddressFactory()
            .getDefaultAddressSpace()
            .getAddress(hex(complex_block.virtual_address))
        )
        func = flat_api.getFunctionAt(addr)
        if func is None:
            func = flat_api.getFunctionContaining(addr)
        if func is None:
            raise ValueError("Could not get func")
        bb_model = BasicBlockModel(flat_api.getCurrentProgram())
        basic_blocks, data_words = _unpack_complex_block(func, flat_api, bb_model, BigInteger.ONE)

        children = []
        for block, bb in basic_blocks:
            if bb["size"] == 0:
                raise Exception(f"Basic block 0x{bb['virtual_address']:x} has no size")

            if (
                bb["virtual_address"] < complex_block.virtual_address
                or (bb["virtual_address"] + bb["size"]) > complex_block.end_vaddr()
            ):
                LOGGER.warning(
                    f"Basic Block 0x{bb['virtual_address']:x} does not fall "
                    f"within complex block "
                    f"{hex(complex_block.virtual_address)}-"
                    f"{hex(complex_block.end_vaddr())}"
                )
                continue
            mode = InstructionSetMode.NONE
            if "mode" in bb:
                mode = InstructionSetMode[bb["mode"].upper()]
            children.append(
                BasicBlock(
                    virtual_address=bb["virtual_address"],
                    size=bb["size"],
                    mode=mode,
                    is_exit_point=bb["is_exit_point"],
                    exit_vaddr=bb["exit_vaddr"],
                )
            )
        for data_word in data_words:
            if (
                data_word["virtual_address"] < complex_block.virtual_address
                or (data_word["virtual_address"] + data_word["size"]) > complex_block.end_vaddr()
            ):
                LOGGER.warning(
                    f"Data Word 0x{data_word['virtual_address']:x} does not fall "
                    f"within complex block "
                    f"{hex(complex_block.virtual_address)}-"
                    f"{hex(complex_block.end_vaddr())}"
                )
                continue
            fmt_string = (
                program_attributes.endianness.get_struct_flag() + data_word["format_string"]
            )
            children.append(
                DataWord(
                    virtual_address=data_word["virtual_address"],
                    size=data_word["size"],
                    format_string=fmt_string,
                    xrefs_to=tuple(data_word["xrefs_to"]),
                )
            )
        for child in children:
            await complex_block.create_child_region(child)


class PyGhidraBasicBlockUnpacker(BasicBlockUnpacker):
    """
    Uses Ghidra to disassemble basic blocks into individual assembly instructions, providing the
    finest-grained view of executable code. Each instruction is extracted with its mnemonic,
    operands, and address. Use when you need instruction-level analysis, want to examine specific
    assembly operations, or are preparing for instruction-level modifications. This is the deepest
    level of code structure extraction.
    """

    id = b"PyGhidraBasicBlockUnpacker"

    def __init__(
        self,
        resource_factory: ResourceFactory,
        data_service: DataServiceInterface,
        resource_service: ResourceServiceInterface,
        analysis_store: PyGhidraAnalysisStore,
        component_locator: ComponentLocatorInterface,
    ):
        super().__init__(resource_factory, data_service, resource_service, component_locator)
        self.analysis_store = analysis_store

    async def unpack(self, resource: Resource, config=None):
        program_r = await resource.get_only_ancestor(ResourceFilter.with_tags(PyGhidraProject))
        program_attributes = await program_r.analyze(ProgramAttributes)
        flat_api = self.analysis_store.get_flat_api(program_r.get_id())
        if flat_api is None:
            raise ValueError("Something's off!")
        bb_view = await resource.view_as(BasicBlock)

        from ghidra.program.model.block import BasicBlockModel
        from ghidra.program.model.symbol import RefType
        from java.math import BigInteger

        program = flat_api.getCurrentProgram()
        bb_model = BasicBlockModel(flat_api.getCurrentProgram())
        addr = (
            program.getAddressFactory()
            .getDefaultAddressSpace()
            .getAddress(hex(bb_view.virtual_address))
        )
        block = bb_model.getCodeBlockAt(addr, flat_api.monitor)
        instructions = _unpack_basic_block(block, flat_api, RefType, BigInteger.ONE)
        for instruction in instructions:
            mode = InstructionSetMode.NONE
            if instruction["mode"] == "thumb":
                mode = InstructionSetMode.THUMB
            elif instruction["mode"] == "vle":
                mode = InstructionSetMode.VLE
            instr = Instruction(
                virtual_address=instruction["virtual_address"],
                size=instruction["size"],
                mnemonic=instruction["mnemonic"],
                operands=instruction["operands"],
                mode=mode,
            )
            await bb_view.create_child_region(instr)


class PyGhidraDecompilationAnalyzer(DecompilationAnalyzer):
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
        program_r = await resource.get_only_ancestor(ResourceFilter.with_tags(PyGhidraProject))
        flat_api = self.analysis_store.get_flat_api(program_r.get_id())
        if flat_api is None:
            raise ValueError("Something is up!")
        complex_block = await resource.view_as(ComplexBlock)

        from ghidra.app.decompiler import DecompInterface, DecompileOptions
        from ghidra.util.task import TaskMonitor

        program = flat_api.getCurrentProgram()
        addr = (
            program.getAddressFactory()
            .getDefaultAddressSpace()
            .getAddress(complex_block.virtual_address)
        )
        func = program.getFunctionManager().getFunctionContaining(addr)
        if func is None:
            raise RuntimeError(f"No function found at 0x{complex_block.virtual_address:x}")

        decomp = DecompInterface()
        options = DecompileOptions()
        options.grabFromProgram(program)
        decomp.setOptions(options)
        decomp.openProgram(program)

        result = decomp.decompileFunction(func, 0, TaskMonitor.DUMMY)
        if not result.decompileCompleted():
            raise RuntimeError(
                f"Unable to decompile function at 0x{complex_block.virtual_address:x}"
            )
        resource.add_tag(DecompilationAnalysis)
        return DecompilationAnalysis(result.getDecompiledFunction().getC())


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
