from ofrak.core import *
import json
import hashlib
from typing import Dict, Any
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

    def store_analysis(self, resource_id: bytes, filename: str):
        with open(filename, "r") as fh:
            analysis = json.load(fh)
            if resource_id not in self.analysis.keys():
                self.analysis[resource_id] = dict()
            self.analysis[resource_id]["analysis"] = analysis

    def store_program_attributes(self, resource_id: bytes, program_attributes: ProgramAttributes):
        if resource_id not in self.analysis.keys():
            self.analysis[resource_id] = dict()
        self.analysis[resource_id]["program_attributes"] = program_attributes

    def delete_id_from_store(self, resource_id: bytes):
        if resource_id in self.analysis:
            del self.analysis[resource_id]

    def get_analysis(self, resource_id: bytes) -> Dict[str, Any]:
        return self.analysis[resource_id]["analysis"]

    def get_program_attributes(self, resource_id: bytes) -> ProgramAttributes:
        return self.analysis[resource_id]["program_attributes"]


@dataclass
class CachedAnalysis(ResourceView):
    pass


@dataclass
class CachedAnalysisAnalyzerConfig(ComponentConfig):
    filename: str
    force: Optional[bool] = False


class CachedAnalysisAnalyzer(Analyzer[CachedAnalysisAnalyzerConfig, CachedAnalysis]):
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
        if not resource.has_tag(Program) and not resource.has_attributes(ProgramAttributes):
            raise AttributeError(
                f"The reource with ID {resource.get_id()} is not an analyzable program format and does not have ProgramAttributes set."
            )
        await resource.unpack()  # Must unpack ELF to get program attributes
        program_attributes = await resource.analyze(ProgramAttributes)
        self.analysis_store.store_analysis(resource.get_id(), config.filename)
        if not config.force:
            if not self.verify_cache_file(resource):
                raise ValueError("MD5 recorded in cache file does not match the hash of the requested resource, use the force config option to use this cache file anyway.")
        self.analysis_store.store_program_attributes(resource.get_id(), program_attributes)
        cached_analysis_view = CachedAnalysis()
        resource.add_view(cached_analysis_view)
        await resource.save()
        return cached_analysis_view

    async def verify_cache_file(self, resource: Resource):
        data = await resource.get_data()
        md5_hash = hashlib.md5(data)
        import ipdb; ipdb.set_trace()
        return md5_hash.digest().hex() == self.analysis_store.get_analysis(resource.get_id())["metadata"]["hash"]


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
        analysis = self.analysis_store.get_analysis(resource.get_id())
        for key, mem_region in analysis.items():
            if key.startswith("seg"):
                await resource.create_child_from_view(CodeRegion(
                    virtual_address=mem_region["virtual_address"], size=mem_region["size"]
                ))

class CachedCodeRegionModifier(Modifier[None]):
    targets=(CodeRegion,)
    
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
        program_r = await resource.get_only_ancestor(ResourceFilter.with_tags(Program))
        analysis = self.analysis_store.get_analysis(program_r.get_id())
        ofrak_code_regions = await program_r.get_descendants_as_view(
            v_type=CodeRegion, r_filter=ResourceFilter(tags=[CodeRegion])
        )
        backend_code_regions: List[CodeRegion] = []
        for key, mem_region in analysis.items():
            if key.startswith("seg"):
                backend_code_regions.append(CodeRegion(
                    virtual_address=mem_region["virtual_address"], size=mem_region["size"]
                ))

        ofrak_code_regions = sorted(ofrak_code_regions, key=lambda cr: cr.virtual_address)
        backend_code_regions = sorted(backend_code_regions, key=lambda cr: cr.virtual_address)

        if len(ofrak_code_regions) > 0:
            code_region = await resource.view_as(CodeRegion)
            relative_va = code_region.virtual_address - ofrak_code_regions[0].virtual_address

            for backend_cr in backend_code_regions:
                backend_relative_va = (
                    backend_cr.virtual_address - backend_code_regions[0].virtual_address
                )
                if backend_relative_va == relative_va and backend_cr.size == code_region.size:
                    code_region.resource.add_view(backend_cr)  # TODO: https://github.com/redballoonsecurity/ofrak/issues/537
        await resource.save()


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
        program_r = await resource.get_only_ancestor(ResourceFilter.with_tags(Program))
        analysis = self.analysis_store.get_analysis(program_r.get_id())
        if analysis["metadata"]["backend"] == "ghidra":
            await resource.run(CachedCodeRegionModifier)
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
        program_r = await resource.get_only_ancestor(ResourceFilter.with_tags(Program))
        analysis = self.analysis_store.get_analysis(program_r.get_id())
        program_attributes = self.analysis_store.get_program_attributes(program_r.get_id())

        cb_view = await resource.view_as(ComplexBlock)
        child_keys = analysis[f"func_{cb_view.virtual_address}"]["children"]
        for children in child_keys:
            if children.startswith("bb"):
                basic_block = analysis[children]
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
        program_r = await resource.get_only_ancestor(ResourceFilter.with_tags(Program))
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
                disassembly=f"{instruction['mnemonic']} {instruction['operands']}",
                mnemonic=instruction["mnemonic"],
                operands=instruction["operands"],
                mode=mode,
            )
            await bb_view.create_child_region(instr)
