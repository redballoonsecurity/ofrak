import logging

from ofrak.core import *
import json
from typing import Dict
from ofrak.core.code_region import CodeRegion
from ofrak.core.complex_block import ComplexBlock

_GHIDRA_AUTO_LOADABLE_FORMATS = [Elf, Ihex, Pe]


@dataclass
class CachedAnalysis(ResourceView):
    analysis: Dict[str, Dict]
    program_attributes: ProgramAttributes


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

    async def analyze(self, resource: Resource, config: CachedAnalysisAnalyzerConfig):
        program_attributes = await resource.analyze(ProgramAttributes)
        with open(config.filename, "r") as fh:
            analysis = json.load(fh)
        cached_analysis_view = CachedAnalysis(
            analysis=analysis, program_attributes=program_attributes
        )
        resource.add_view(cached_analysis_view)
        await resource.save()
        return cached_analysis_view


class CachedProgramUnpacker(Unpacker[None]):
    targets = (CachedAnalysis,)
    outputs = (CodeRegion,)

    async def unpack(self, resource: Resource, config: None):
        cached_analysis_view = await resource.view_as(CachedAnalysis)
        cached_analysis = cached_analysis_view.analysis
        for key, mem_region in cached_analysis.items():
            if key.startswith("seg"):
                cr = CodeRegion(
                    virtual_address=mem_region["virtual_address"], size=mem_region["size"]
                )
            await resource.create_child_from_view(cr)


class CachedCodeRegionUnpacker(CodeRegionUnpacker):
    async def unpack(self, resource: Resource, config: None):
        try:
            analysis_parent = await resource.get_only_ancestor_as_view(
                v_type=CachedAnalysis, r_filter=ResourceFilter(tags=(CachedAnalysis,))
            )
        except NotFoundError:
            logging.error(
                "Can not find CachedAnalysis, must run CachedAnalysisAnalyzer manually with the cache file specified."
            )
            raise

        cached_analysis = analysis_parent.analysis
        code_region_view = await resource.view_as(CodeRegion)
        key = f"seg_{code_region_view.virtual_address}"
        func_keys = cached_analysis[key]["children"]
        for func_key in func_keys:
            complex_block = cached_analysis[func_key]
            cb = ComplexBlock(
                virtual_address=complex_block["virtual_address"],
                size=complex_block["size"],
                name=complex_block["name"],
            )
            await code_region_view.create_child_region(cb)


class CachedComplexBlockUnpacker(ComplexBlockUnpacker):
    async def unpack(self, resource: Resource, config: None):
        try:
            analysis_parent = await resource.get_only_ancestor_as_view(
                v_type=CachedAnalysis, r_filter=ResourceFilter(tags=(CachedAnalysis,))
            )
        except NotFoundError:
            logging.error(
                "Can not find CachedAnalysis, must run CachedAnalysisAnalyzer manually with the cache file specified."
            )
            raise

        cached_analysis = analysis_parent.analysis
        cb_view = await resource.view_as(ComplexBlock)
        key = f"func_{cb_view.virtual_address}"
        child_keys = cached_analysis[key]["children"]
        for children in child_keys:
            if children.startswith("bb"):
                basic_block = cached_analysis[children]
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
                data_word = cached_analysis[children]
                fmt_string = (
                    analysis_parent.program_attributes.endianness.get_struct_flag()
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
    async def unpack(self, resource: Resource, config: None):
        try:
            analysis_parent = await resource.get_only_ancestor_as_view(
                v_type=CachedAnalysis, r_filter=ResourceFilter(tags=(CachedAnalysis,))
            )
        except NotFoundError:
            logging.error(
                "Can not find CachedAnalysis, must run CachedAnalysisAnalyzer manually with the cache file specified."
            )
            raise
        cached_analysis = analysis_parent.analysis
        bb_view = await resource.view_as(BasicBlock)
        key = f"bb_{bb_view.virtual_address}"
        child_keys = cached_analysis[key]["children"]
        for children in child_keys:
            instruction = cached_analysis[children]
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
