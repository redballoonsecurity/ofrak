import logging

from ofrak.core import *
import json
from typing import Dict
from ofrak.core.code_region import CodeRegion
from ofrak.core.complex_block import ComplexBlock
from ofrak.service.component_locator_i import (
    ComponentLocatorInterface,
)

_GHIDRA_AUTO_LOADABLE_FORMATS = [Elf, Ihex, Pe]


class CachedAnalysisStore:
    def __init__(self):
        self.analysis = dict()
        self.program_attributes: Optional[ProgramAttributes] = None

    def store_analysis(self, filename):
        with open(filename, "r") as fh:
            self.analysis = json.load(fh)

    def store_program_attributes(self, program_attributes: ProgramAttributes):
        self.program_attributes = program_attributes


@dataclass
class CachedAnalysis(ResourceView):
    pass


class CachedAnalysisIdentifier(Identifier):
    id = b"CachedAnalysisIdentifier"
    targets = (Program,)

    async def identify(self, resource: Resource, config=None):
        for tag in _GHIDRA_AUTO_LOADABLE_FORMATS:
            if resource.has_tag(tag):
                resource.add_tag(CachedAnalysis)


@dataclass
class CachedAnalysisAnalyzerConfig(ComponentConfig):
    filename: str


class CachedAnalysisAnalyzer(Analyzer[CachedAnalysisAnalyzerConfig, CachedAnalysis]):
    id = b"CachedAnalysisAnalyzer"
    targets = (None,)
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
        program_attributes = await resource.analyze(ProgramAttributes)
        self.analysis_store.store_analysis(config.filename)
        self.analysis_store.store_program_attributes(program_attributes)
        cached_analysis_view = CachedAnalysis()
        await resource.save()
        return cached_analysis_view


class CachedProgramUnpacker(Unpacker[None]):
    targets = (CachedAnalysis,)
    outputs = (CodeRegion,)

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
        for key, mem_region in self.analysis_store.items():
            if key.startswith("seg"):
                cr = CodeRegion(
                    virtual_address=mem_region["virtual_address"], size=mem_region["size"]
                )
                await resource.create_child_from_view(cr)


class CachedCodeRegionUnpacker(CodeRegionUnpacker):
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
        code_region_view = await resource.view_as(CodeRegion)
        key = f"seg_{code_region_view.virtual_address}"
        func_keys = self.analysis_store.analysis[key]["children"]
        for func_key in func_keys:
            complex_block = self.analysis_store.analysis[func_key]
            cb = ComplexBlock(
                virtual_address=complex_block["virtual_address"],
                size=complex_block["size"],
                name=complex_block["name"],
            )
            await code_region_view.create_child_region(cb)


class CachedComplexBlockUnpacker(ComplexBlockUnpacker):
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
        cb_view = await resource.view_as(ComplexBlock)
        key = f"func_{cb_view.virtual_address}"
        child_keys = self.analysis_store.analysis[key]["children"]
        for children in child_keys:
            if children.startswith("bb"):
                basic_block = self.analysis_store.analysis[children]
                mode = InstructionSetMode.NONE
                if basic_block["mode"] == "thumb":
                    mode = InstructionSetMode.THUMB
                elif basic_block["mode"] == "vle":
                    mode = InstructionSetMode.VLE
                bb = BasicBlock(
                    virtual_address=basic_block["virtual_address"],
                    size=basic_block["size"],
                    mode=mode,
                    is_exit_point=basic_block["is_exit_point"],
                    exit_vaddr=basic_block["exit_vaddr"],
                )
                await cb_view.create_child_region(bb)
            elif children.startswith("dw"):
                data_word = self.analysis_store.analysis[children]
                fmt_string = (
                    self.analysis_store.program_attributes.endianness.get_struct_flag()
                    + data_word["format_string"]
                )
                dw = DataWord(
                    virtual_address=data_word["virtual_address"],
                    size=data_word["size"],
                    format_string=fmt_string,
                    xrefs_to=tuple(data_word["xrefs_to"]),
                )
                await cb_view.create_child_region(dw)


class CachedBasicBlockUnpacker(BasicBlockUnpacker):
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
        bb_view = await resource.view_as(BasicBlock)
        key = f"bb_{bb_view.virtual_address}"
        child_keys = self.analysis_store.analysis[key]["children"]
        for children in child_keys:
            instruction = self.analysis_store.analysis[children]
            mode = InstructionSetMode.NONE
            if instruction["mode"] == "thumb":
                mode = InstructionSetMode.THUMB
            elif instruction["mode"] == "vle":
                mode = InstructionSetMode.VLE
            instr = Instruction(
                virtual_address=instruction["virtual_address"],
                size=instruction["size"],
                disassembly=f"{instruction['mnemonic']} {instruction['operands']}",
                mnemonic=instruction["mnemonic"],
                operands=instruction["operands"],
                mode=mode,
            )
            await bb_view.create_child_region(instr)
