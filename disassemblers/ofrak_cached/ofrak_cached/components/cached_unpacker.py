import logging

from ofrak.core import *
import json

from ofrak.core.code_region import CodeRegion
from ofrak.core.complex_block import ComplexBlock

_GHIDRA_AUTO_LOADABLE_FORMATS = [Elf, Ihex, Pe]


@dataclass
class CachedAnalysis(ResourceView):
    filename: str
    program_attributes: ProgramAttributes

    def cached_analysis(self):
        with open(self.filename, "r") as fh:
            return json.load(fh)


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
        cached_analysis_view = CachedAnalysis(
            filename=config.filename, program_attributes=program_attributes
        )
        resource.add_view(cached_analysis_view)
        await resource.save()
        return cached_analysis_view


class CachedProgramUnpacker(Unpacker[None]):
    targets = (CachedAnalysis,)
    outputs = (CodeRegion,)

    async def unpack(self, resource: Resource, config: None):
        cached_analysis_view = await resource.view_as(CachedAnalysis)
        cached_analysis = cached_analysis_view.cached_analysis()
        for code_region in cached_analysis:
            cr = CodeRegion(
                virtual_address=code_region["virtual_address"], size=code_region["size"]
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

        cached_analysis = analysis_parent.cached_analysis()
        code_region_view = await resource.view_as(CodeRegion)
        for code_region in cached_analysis:
            if code_region["virtual_address"] == code_region_view.virtual_address:
                for complex_block in code_region["complex_blocks"]:
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

        cached_analysis = analysis_parent.cached_analysis()
        cb_view = await resource.view_as(ComplexBlock)

        for code_region in cached_analysis:
            if (
                cb_view.virtual_address > code_region["virtual_address"]
                and cb_view.virtual_address < code_region["virtual_address"] + code_region["size"]
            ):
                for complex_block in code_region["complex_blocks"]:
                    if complex_block["virtual_address"] == cb_view.virtual_address:
                        for basic_block in complex_block["basic_blocks"]:
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
                        for data_word in complex_block["data_words"]:
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
        cached_analysis = analysis_parent.cached_analysis()
        bb_view = await resource.view_as(BasicBlock)

        for code_region in cached_analysis:
            if (
                bb_view.virtual_address > code_region["virtual_address"]
                and bb_view.virtual_address < code_region["virtual_address"] + code_region["size"]
            ):
                for complex_block in code_region["complex_blocks"]:
                    if (
                        bb_view.virtual_address > complex_block["virtual_address"]
                        and bb_view.virtual_address
                        < complex_block["virtual_address"] + complex_block["size"]
                    ):
                        for basic_block in complex_block["basic_blocks"]:
                            if basic_block["virtual_address"] == bb_view.virtual_address:
                                for instruction in basic_block["instructions"]:
                                    mode = InstructionSetMode.NONE
                                    if basic_block["mode"] == "thumb":
                                        mode = InstructionSetMode.THUMB
                                    elif basic_block["mode"] == "vle":
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
