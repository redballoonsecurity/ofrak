import hashlib
from typing import List, Optional
from dataclasses import dataclass

from ofrak.component.modifier import Modifier
from ofrak.core import Analyzer, ComponentConfig, ResourceFactory
from ofrak.core.architecture import ProgramAttributes
from ofrak.core.basic_block import BasicBlock, BasicBlockUnpacker
from ofrak.core.code_region import CodeRegion, CodeRegionUnpacker
from ofrak.core.complex_block import ComplexBlock, ComplexBlockUnpacker
from ofrak.core.data import DataWord
from ofrak.core.instruction import Instruction
from ofrak.service.component_locator_i import (
    ComponentLocatorInterface,
)
from ofrak.core.decompilation import (
    DecompilationAnalysis,
    DecompilationAnalyzer,
    DecompilationAnalysis,
    ResourceView,
)

from ofrak.core.elf.model import Elf, ElfHeader, ElfType
from ofrak.core.ihex import Ihex
from ofrak.core.pe.model import Pe
from ofrak.service.data_service_i import DataServiceInterface
from ofrak.service.resource_service_i import ResourceFilter, ResourceServiceInterface
from ofrak_cached_disassembly.components.cached_disassembly import CachedAnalysisStore
from ofrak.resource import Resource

from ofrak.component.unpacker import Unpacker
from ofrak.core.program import Program
from ofrak_type.architecture import InstructionSetMode

_GHIDRA_AUTO_LOADABLE_FORMATS = [Elf, Ihex, Pe]


@dataclass
class CachedAnalysis(ResourceView):
    pass


@dataclass
class CachedAnalysisAnalyzerConfig(ComponentConfig):
    """
    This config is used to pass the filename of the cache json file to the analyzer.

    :param filename:The path to the cache json file.
    :param force: Set to True to force the analyzer to use the cache file even if the hash does not match. Defaults to False.
    """

    filename: str
    force: Optional[bool] = False


class CachedAnalysisAnalyzer(Analyzer[CachedAnalysisAnalyzerConfig, CachedAnalysis]):
    """
    This analyzer maps the cached analysis to the resource and verifies it's metadata.
    """

    id = b"CachedAnalysisAnalyzer"
    targets = (CachedAnalysis,)
    outputs = (CachedAnalysis,)

    def __init__(
        self,
        resource_factory: ResourceFactory,
        data_service: DataServiceInterface,
        resource_service: ResourceServiceInterface,
        analysis_store: CachedAnalysisStore,
    ):
        super().__init__(resource_factory, data_service, resource_service)
        self.analysis_store = analysis_store

    async def analyze(self, resource: Resource, config: CachedAnalysisAnalyzerConfig):
        await resource.identify()
        if not (
            resource.has_tag(Program) or resource.has_tag(Ihex)
        ) and not resource.has_attributes(ProgramAttributes):
            raise AttributeError(
                f"The resource with ID {resource.get_id()} is not an analyzable program format and does not have ProgramAttributes set."
            )
        self.analysis_store.store_analysis(resource.get_id(), config.filename)
        if not config.force:
            if not await self.verify_cache_file(resource):
                raise ValueError(
                    "MD5 recorded in cache file does not match the hash of the requested resource, use the force config option to use this cache file anyway."
                )
        # unpack must come after store_analysis so the resource id lookup does not fail
        await resource.unpack()  # Must unpack ELF to get program attributes
        program_attributes = await resource.analyze(ProgramAttributes)
        self.analysis_store.store_program_attributes(resource.get_id(), program_attributes)
        cached_analysis_view = CachedAnalysis()
        resource.add_view(cached_analysis_view)
        await resource.save()
        return cached_analysis_view

    async def verify_cache_file(self, resource: Resource):
        data = await resource.get_data()
        md5_hash = hashlib.md5(data)
        return (
            md5_hash.digest().hex()
            == self.analysis_store.get_analysis(resource.get_id())["metadata"]["hash"]
        )


class CachedProgramUnpacker(Unpacker[None]):
    """
    Extracts segments from the cache and creates CodeRegions for each.
    """

    targets = (CachedAnalysis,)
    children = (CodeRegion,)

    def __init__(
        self,
        resource_factory: ResourceFactory,
        data_service: DataServiceInterface,
        resource_service: ResourceServiceInterface,
        analysis_store: CachedAnalysisStore,
        component_locator: ComponentLocatorInterface,
    ):
        super().__init__(resource_factory, data_service, resource_service, component_locator)
        self.analysis_store = analysis_store

    async def unpack(self, resource: Resource, config: None):
        analysis = self.analysis_store.get_analysis(resource.get_id())
        for key, mem_region in analysis.items():
            if key.startswith("seg"):
                await resource.create_child_from_view(
                    CodeRegion(
                        virtual_address=mem_region["virtual_address"], size=mem_region["size"]
                    )
                )


class CachedGhidraCodeRegionModifier(Modifier[None]):
    """
    Ghidra uses a different base address than the ELF does, so we have to rebase the ghidra analysis to the ELF addresses.
    """

    targets = (CodeRegion,)

    def __init__(
        self,
        resource_factory: ResourceFactory,
        data_service: DataServiceInterface,
        resource_service: ResourceServiceInterface,
        analysis_store: CachedAnalysisStore,
    ):
        super().__init__(resource_factory, data_service, resource_service)
        self.analysis_store = analysis_store

    async def modify(self, resource: Resource, config: None):
        program_r = await resource.get_only_ancestor(ResourceFilter.with_tags(CachedAnalysis))
        analysis = self.analysis_store.get_analysis(program_r.get_id())
        ofrak_code_regions = await program_r.get_descendants_as_view(
            v_type=CodeRegion, r_filter=ResourceFilter(tags=[CodeRegion])
        )
        backend_code_regions: List[CodeRegion] = []
        for key, mem_region in analysis.items():
            if key.startswith("seg") and mem_region["executable"]:
                backend_code_regions.append(
                    CodeRegion(
                        virtual_address=mem_region["virtual_address"], size=mem_region["size"]
                    )
                )

        ofrak_code_regions = sorted(ofrak_code_regions, key=lambda cr: cr.virtual_address)
        backend_code_regions = sorted(backend_code_regions, key=lambda cr: cr.virtual_address)

        # We only want to adjust the address of a CodeRegion if the original binary is position-independent.
        # Implement PIE-detection for other file types as necessary.
        if program_r.has_tag(Elf):
            elf_header = await program_r.get_only_descendant_as_view(
                ElfHeader, r_filter=ResourceFilter(tags=[ElfHeader])
            )
            if elf_header is not None and elf_header.e_type == ElfType.ET_DYN.value:
                fixup_address = True
        else:
            LOGGER.warning(
                f"Have not implemented PIE-detection for {root_resource}. The address of {code_region} will likely be incorrect."
            )
        if fixup_address:
            # import here to avoid circular dependencies
            from ofrak_pyghidra.components.pyghidra_components import PyGhidraProject

            pyghidra_project_r = await resource.get_only_ancestor(
                ResourceFilter.with_tags(PyGhidraProject)
            )
            pyghidra_project_v = await pyghidra_project_r.view_as(PyGhidraProject)

            code_region = await resource.view_as(CodeRegion)
            if pyghidra_project_v.base_address:
                new_cr = CodeRegion(
                    code_region.virtual_address + pyghidra_project_v.base_address, code_region.size
                )
                code_region.resource.add_view(new_cr)
            elif len(ofrak_code_regions) > 0:
                relative_va = code_region.virtual_address - ofrak_code_regions[0].virtual_address

                for backend_cr in backend_code_regions:
                    backend_relative_va = (
                        backend_cr.virtual_address - backend_code_regions[0].virtual_address
                    )
                    if backend_relative_va == relative_va and backend_cr.size == code_region.size:
                        code_region.resource.add_view(backend_cr)
                        pyghidra_project_r.add_view(
                            PyGhidraProject(
                                base_address=backend_cr.virtual_address
                                - code_region.virtual_address
                            )
                        )
                        await pyghidra_project_r.save()
            await resource.save()


class CachedCodeRegionUnpacker(CodeRegionUnpacker):
    """
    Unpacks complex from a CodeRegion resource via its cached children.
    """

    def __init__(
        self,
        resource_factory: ResourceFactory,
        data_service: DataServiceInterface,
        resource_service: ResourceServiceInterface,
        analysis_store: CachedAnalysisStore,
        component_locator: ComponentLocatorInterface,
    ):
        super().__init__(resource_factory, data_service, resource_service, component_locator)
        self.analysis_store = analysis_store

    async def unpack(self, resource: Resource, config: None):
        program_r = await resource.get_only_ancestor(ResourceFilter.with_tags(CachedAnalysis))
        analysis = self.analysis_store.get_analysis(program_r.get_id())
        if analysis["metadata"]["backend"] == "ghidra":
            await resource.run(CachedGhidraCodeRegionModifier)
        code_region_view = await resource.view_as(CodeRegion)
        func_keys = analysis[f"seg_{code_region_view.virtual_address}"]["children"]
        for func_key in func_keys:
            complex_block = analysis[func_key]
            cb = ComplexBlock(
                virtual_address=complex_block["virtual_address"],
                size=complex_block["size"],
                name=complex_block["name"],
            )
            await code_region_view.create_child_region(cb)


class CachedComplexBlockUnpacker(ComplexBlockUnpacker):
    """
    Unpacks a complex block into its basic blocks and data words using the dw and bb keys in the cache json file.
    """

    def __init__(
        self,
        resource_factory: ResourceFactory,
        data_service: DataServiceInterface,
        resource_service: ResourceServiceInterface,
        analysis_store: CachedAnalysisStore,
        component_locator: ComponentLocatorInterface,
    ):
        super().__init__(resource_factory, data_service, resource_service, component_locator)
        self.analysis_store = analysis_store

    async def unpack(self, resource: Resource, config: None):
        program_r = await resource.get_only_ancestor(ResourceFilter.with_tags(CachedAnalysis))
        analysis = self.analysis_store.get_analysis(program_r.get_id())
        program_attributes = self.analysis_store.get_program_attributes(program_r.get_id())
        if program_attributes is None:
            program_attributes = await resource.analyze(ProgramAttributes)

        cb_view = await resource.view_as(ComplexBlock)
        child_keys = analysis[f"func_{cb_view.virtual_address}"]["children"]
        for children in child_keys:
            if children.startswith("bb"):
                basic_block = analysis[children]
                mode = InstructionSetMode.NONE
                if "mode" in basic_block:
                    mode = InstructionSetMode[basic_block["mode"].upper()]
                bb = BasicBlock(
                    virtual_address=basic_block["virtual_address"],
                    size=basic_block["size"],
                    mode=mode,
                    is_exit_point=basic_block["is_exit_point"],
                    exit_vaddr=basic_block["exit_vaddr"],
                )
                await cb_view.create_child_region(bb)
            elif children.startswith("dw"):
                data_word = analysis[children]
                fmt_string = (
                    program_attributes.endianness.get_struct_flag() + data_word["format_string"]
                )
                dw = DataWord(
                    virtual_address=data_word["virtual_address"],
                    size=data_word["size"],
                    format_string=fmt_string,
                    xrefs_to=tuple(data_word["xrefs_to"]),
                )
                await cb_view.create_child_region(dw)


class CachedBasicBlockUnpacker(BasicBlockUnpacker):
    """
    Unpacks a basic block into its instructions using the instr key in the cache json file.
    """

    def __init__(
        self,
        resource_factory: ResourceFactory,
        data_service: DataServiceInterface,
        resource_service: ResourceServiceInterface,
        analysis_store: CachedAnalysisStore,
        component_locator: ComponentLocatorInterface,
    ):
        super().__init__(resource_factory, data_service, resource_service, component_locator)
        self.analysis_store = analysis_store

    async def unpack(self, resource: Resource, config: None):
        program_r = await resource.get_only_ancestor(ResourceFilter.with_tags(CachedAnalysis))
        analysis = self.analysis_store.get_analysis(program_r.get_id())

        bb_view = await resource.view_as(BasicBlock)
        child_keys = analysis[f"bb_{bb_view.virtual_address}"]["children"]
        for children in child_keys:
            instruction = analysis[children]
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


class CachedDecompilationAnalyzer(DecompilationAnalyzer):
    """
    This analyzer extracts the decompilation from the cache json file and adds it to the resource if it exists.
    """

    targets = (ComplexBlock,)
    outputs = (DecompilationAnalysis,)

    def __init__(
        self,
        resource_factory: ResourceFactory,
        data_service: DataServiceInterface,
        resource_service: ResourceServiceInterface,
        analysis_store: CachedAnalysisStore,
    ):
        super().__init__(resource_factory, data_service, resource_service)
        self.analysis_store = analysis_store

    async def analyze(self, resource: Resource, config: None) -> DecompilationAnalysis:
        # Run / fetch ghidra analyzer
        program_r = await resource.get_only_ancestor(ResourceFilter.with_tags(CachedAnalysis))
        analysis = self.analysis_store.get_analysis(program_r.get_id())
        complex_block = await resource.view_as(ComplexBlock)
        if "decompilation" in analysis[f"func_{complex_block.virtual_address}"]:
            decomp = analysis[f"func_{complex_block.virtual_address}"]["decompilation"]
        else:
            decomp = "The cache file does not contain a decompilation for this function."
        resource.add_tag(DecompilationAnalysis)
        await resource.save()
        return DecompilationAnalysis(decomp)
