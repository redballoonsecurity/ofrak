import logging
from typing import Iterable, Tuple, List
from typing import Optional
from warnings import warn

from angr.knowledge_plugins.functions.function import Function as AngrFunction
from archinfo.arch_arm import get_real_address_if_arm, is_arm_arch

from ofrak.component.unpacker import UnpackerError
from ofrak_type.architecture import InstructionSetMode
from ofrak_type.range import Range

from ofrak.core.basic_block import BasicBlock
from ofrak.core.code_region import CodeRegionUnpacker, CodeRegion
from ofrak.core.complex_block import ComplexBlock, ComplexBlockUnpacker
from ofrak.core.data import DataWord
from ofrak.resource import Resource
from ofrak.service.resource_service_i import ResourceFilter
from ofrak_angr.components.angr_analyzer import AngrAnalyzerConfig, AngrCodeRegionModifier
from ofrak_angr.components.identifiers import AngrAnalysisResource
from ofrak_angr.model import AngrAnalysis

LOGGER = logging.getLogger(__name__)


class AngrCodeRegionUnpacker(CodeRegionUnpacker):
    async def unpack(self, resource: Resource, config: Optional[AngrAnalyzerConfig] = None):
        # Prepare CR unpacker
        cr_view = await resource.view_as(CodeRegion)

        # Run AngrAnalyzer
        root_resource = await resource.get_only_ancestor(
            ResourceFilter(tags=[AngrAnalysisResource], include_self=True)
        )
        angr_analysis = await root_resource.analyze(AngrAnalysis)

        # Fixup the CodeRegion's virtual address after analyzing with angr.
        await resource.run(AngrCodeRegionModifier, None)

        cr_vaddr_range = cr_view.vaddr_range()

        # Fetch and create complex blocks to populate the CR with
        num_overlapping_cbs = 0

        for complex_block in self._angr_get_complex_blocks(angr_analysis, cr_vaddr_range):
            await cr_view.create_child_region(complex_block)

        if num_overlapping_cbs > 0:
            LOGGER.warning(
                f"Skipped {num_overlapping_cbs} complex blocks that would have resulted in overlap"
            )

    @staticmethod
    def _angr_get_complex_blocks(
        angr_analysis: AngrAnalysis, region_vaddr: Range
    ) -> Iterable[ComplexBlock]:
        """
        Iterator which yields Complex Blocks derived from the angr CFG within an address range

        :param angr_analysis: angr project state for the binary-under-analysis
        :param region_vaddr: Virtual address range of the code region to unpack complex blocks

        :return: Yield the next Complex Block (sorted by entrypoint address)
        """
        LOGGER.debug(f"Getting complex blocks from region {region_vaddr.start:#x}")

        # Filter for functions within the requested region
        angr_funcs: Iterable[Tuple[int, AngrFunction]] = angr_analysis.project.kb.functions.items()
        funcs = [f[1] for f in angr_funcs if f[0] in region_vaddr]

        # Filter out non-returning functions, unless it's an entrypoint
        # TODO: Re-visit this; this will likely filter HW interrupt funcs
        funcs = [f for f in funcs if (f.has_return) or (f.addr == angr_analysis.project.entry)]

        # Yield the next function via a generator
        for idx, func in enumerate(funcs):
            start_addr = func.addr

            # Adjust the upper bound of the CB to include DWORDS
            # The boundary of a CB extends up to min(region_end_vaddr, next_func_addr)
            next_idx = idx + 1
            if next_idx < len(funcs):
                end_addr = min(region_vaddr.end, funcs[next_idx].addr)
            else:
                end_addr = region_vaddr.end

            # OFRAK expects real addresses, so we need to convert the thumb-masked addresses angr returns
            start_addr = get_real_address_if_arm(angr_analysis.project.arch, start_addr)
            end_addr = get_real_address_if_arm(angr_analysis.project.arch, end_addr)

            yield ComplexBlock(start_addr, end_addr - start_addr, func.name)


class AngrComplexBlockUnpacker(ComplexBlockUnpacker):
    async def unpack(self, resource: Resource, config: Optional[AngrAnalyzerConfig] = None):
        # Prepare CB unpacker
        cb_view = await resource.view_as(ComplexBlock)
        cb_vaddr_range = cb_view.vaddr_range()
        cb_data_range = await resource.get_data_range_within_root()

        # Run / fetch angr analyzer
        root_resource = await resource.get_only_ancestor(
            ResourceFilter(tags=[AngrAnalysisResource], include_self=True)
        )
        angr_analysis = await root_resource.analyze(AngrAnalysis)

        valid_data_xref_ranges = []
        # Fetch and create Basic Blocks to populate the CB with
        for basic_block in self._angr_get_basic_blocks(angr_analysis, cb_vaddr_range):
            await cb_view.create_child_region(basic_block)
            valid_data_xref_ranges.append(basic_block.vaddr_range())

        valid_data_xref_ranges = Range.merge_ranges(valid_data_xref_ranges)
        # Fetch and create Data Words to populate the CB with
        for data_word in self._angr_get_dword_blocks(
            angr_analysis, cb_vaddr_range, cb_data_range, valid_data_xref_ranges
        ):
            await cb_view.create_child_region(data_word)

    @staticmethod
    def _angr_get_basic_blocks(
        angr_analysis: AngrAnalysis, cb_vaddr_range: Range
    ) -> Iterable[BasicBlock]:
        """
        Iterator which yields Basic Blocks derived from the angr CFG within an address range

        :param angr_analysis: angr project state for the binary-under-analysis
        :param cb_vaddr_range: Total virtual address range of the CB

        :return: Yield the next Basic Block (sorted by entrypoint address)
        """
        LOGGER.debug(f"Getting basic blocks from function {cb_vaddr_range.start:#x}")

        angr_complex_block = angr_analysis.project.kb.functions.function(addr=cb_vaddr_range.start)
        if not angr_complex_block and is_arm_arch(angr_analysis.project.arch):
            thumb_cb_vaddr = cb_vaddr_range.start | 0x1
            angr_complex_block = angr_analysis.project.kb.functions.function(addr=thumb_cb_vaddr)

        if not angr_complex_block:
            LOGGER.error(f"Could not find complex block at {cb_vaddr_range.start:#x} in angr")
            return

        angr_cb_basic_blocks = sorted(list(angr_complex_block.blocks), key=lambda bb: bb.addr)
        for idx, bb in enumerate(angr_cb_basic_blocks):
            bb_addr = get_real_address_if_arm(angr_analysis.project.arch, bb.addr)

            bb_mode = InstructionSetMode.NONE
            if is_arm_arch(bb.arch) and (bb.addr & 0x1):
                bb_mode = InstructionSetMode.THUMB

            try:
                bb_is_exit_point, bb_exit_addr = _get_bb_exit_addr_info(
                    angr_analysis,
                    angr_complex_block,
                    angr_cb_basic_blocks,
                    bb,
                    idx,
                )
            except UnpackerError:
                return

            if (bb_addr + bb.size) > cb_vaddr_range.end or bb_addr < cb_vaddr_range.start:
                warning_string = (
                    f"Basic block {bb_addr:#x} does not fall within "
                    f"complex block {cb_vaddr_range.start:#x} at "
                    f"addresses {cb_vaddr_range.start:#x}-{cb_vaddr_range.end:#x}"
                )
                warn(RuntimeWarning(warning_string))
                continue

            yield BasicBlock(
                bb_addr,
                bb.size,
                bb_mode,
                bb_is_exit_point,
                bb_exit_addr,
            )

    @staticmethod
    def _angr_get_dword_blocks(
        angr_analysis: AngrAnalysis,
        cb_data_range: Range,
        cb_vaddr_range: Range,
        valid_data_xref_ranges: List[Range],
    ) -> Iterable[DataWord]:
        """
        Iterator which yields Dword Blocks derived from the angr CFG within an address range

        :param angr_analysis: angr project state for the binary-under-analysis
        :param cb_data_range: Data range of the CB
        :param cb_vaddr_range: Total virtual address range of the CB

        :return: Yield the next DataWord (sorted by address)
        """
        LOGGER.debug(f"Getting data words from function {cb_vaddr_range.start:#x}")

        # Map known dword types and format string specifiers for the dword size
        dword_types = {"integer", "pointer-array"}
        dword_size_map = {1: "B", 2: "H", 4: "L", 8: "Q"}

        # Set the endianness format string specifier
        endian_flag = ">" if angr_analysis.project.arch.instruction_endness.endswith("BE") else "<"

        # Fetch the most accurate CFG (according to angr) to fetch the xref list
        angr_cfg = angr_analysis.project.kb.cfgs.get_most_accurate()
        if not angr_cfg:
            LOGGER.error(
                "No CFGs returned by angr.project.kb.cfg. "
                "This should have been populated by AngrAnalyzer, or "
                "there may be an error in the provided post-analysis hook."
            )
            return

        # Filter xrefs within the requested address range & if known dword type
        cb_data_xrefs = [
            (xref, cb_data_xref)
            for xref, cb_data_xref in angr_cfg.insn_addr_to_memory_data.items()
            if (cb_data_xref.addr in cb_data_range) and (cb_data_xref.sort in dword_types)
        ]

        for xref, cb_data_xref in cb_data_xrefs:
            word_size = cb_data_xref.size
            cb_data_xref_addr = cb_data_xref.addr

            if word_size not in dword_size_map:
                raise ValueError(f"Bad word size {word_size} at {cb_data_xref_addr:#x}")

            if xref is None or not any(xref in bb_range for bb_range in valid_data_xref_ranges):
                continue

            LOGGER.debug(f"Creating DataWord for {cb_data_xref.content!r} @ {cb_data_xref_addr:#x}")

            format_string = endian_flag + dword_size_map[word_size]

            cb_data_xref_addr = get_real_address_if_arm(
                angr_analysis.project.arch, cb_data_xref_addr
            )
            xref = get_real_address_if_arm(angr_analysis.project.arch, xref) if xref else None

            yield DataWord(cb_data_xref_addr, word_size, format_string, (xref,))


def _get_bb_exit_addr_info(
    angr_analysis,
    angr_complex_block,
    angr_cb_basic_blocks,
    current_angr_bb,
    current_bb_idx,
) -> Tuple[bool, Optional[int]]:
    """
    Get exit address info needed for BasicBlock creation:
    BasicBlock.is_exit_point, BasicBlock.exit_addr.
    """
    # Fetch the exit point addr (if it exists) and sanity check the selection
    if current_angr_bb.codenode in angr_complex_block.endpoints:
        return True, None

    if current_bb_idx == len(angr_cb_basic_blocks) - 1:
        LOGGER.error(
            f"Exit point defined for BB 0x{current_angr_bb.addr:x} even though it is the last BB on the addr list"
        )
        raise UnpackerError()

    # If no conditional branches taken, execution "falls through" to next basic block
    fallthrough_vaddr = get_real_address_if_arm(
        angr_analysis.project.arch, angr_cb_basic_blocks[current_bb_idx + 1].addr
    )
    try:
        successor_vaddrs = [
            get_real_address_if_arm(angr_analysis.project.arch, succ_codenode.addr)
            for succ_codenode, edge_info in angr_complex_block.graph.succ[
                current_angr_bb.codenode
            ].items()
        ]
    except KeyError:
        LOGGER.warning(
            f"Cannot find any successors in angr for BB 0x{current_angr_bb.addr:x}, but since it "
            f"has a BB after it, assume that it still falls through to the next BB."
        )
        return True, fallthrough_vaddr

    if fallthrough_vaddr in successor_vaddrs:
        # Basic block can fall through to next block, so the next block should be the exit addr
        return False, fallthrough_vaddr
    else:
        # Basic block can't fall through to next block, choose first succ as exit addr
        # For example: basic block ends in unconditional one-way branch (not a call)
        # If there are somehow multiple successors and the fallthrough block is not one of them,
        # choosing the first succ as the exit addr is arbitrary, but better choice is unclear.
        return False, successor_vaddrs[0]
