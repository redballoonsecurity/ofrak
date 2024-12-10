import asyncio
import logging
from typing import Iterable, Tuple, List
from typing import Optional
from warnings import warn

from binaryninja import BinaryView, Endianness, TypeClass, ReferenceSource, DataVariable
from ofrak_type.architecture import InstructionSetMode
from ofrak_type.range import Range

from ofrak.core.architecture import ProgramAttributes
from ofrak.core.basic_block import BasicBlock
from ofrak.core.code_region import CodeRegionUnpacker, CodeRegion
from ofrak.core.complex_block import ComplexBlock, ComplexBlockStructureError, ComplexBlockUnpacker
from ofrak.core.data import DataWord
from ofrak.core.program import Program
from ofrak.model.component_model import ComponentConfig
from ofrak.resource import Resource
from ofrak.service.resource_service_i import ResourceFilter
from ofrak_binary_ninja.components.identifiers import BinaryNinjaAnalysisResource
from ofrak_binary_ninja.model import BinaryNinjaAnalysis

LOGGER = logging.getLogger(__name__)


MAX_GAP_BETWEEN_FUNC_ADDRESS_RANGE = 0x20


class BinaryNinjaCodeRegionUnpacker(CodeRegionUnpacker):
    async def unpack(self, resource: Resource, config=None):
        region_view = await resource.view_as(CodeRegion)
        program_r = await region_view.resource.get_only_ancestor_as_view(
            Program, ResourceFilter.with_tags(Program)
        )
        program_attrs = await program_r.resource.analyze(ProgramAttributes)
        root_resource = await resource.get_only_ancestor(
            ResourceFilter(tags=[BinaryNinjaAnalysisResource], include_self=True)
        )
        binary_ninja_analysis = await root_resource.analyze(BinaryNinjaAnalysis)
        binaryview = binary_ninja_analysis.binaryview

        region_start_vaddr = region_view.virtual_address
        region_end_vaddr = region_start_vaddr + region_view.size

        skip_count = 0

        for cb_start_ea, cb_end_ea, cb_name in self._binary_ninja_get_complex_blocks(
            binaryview, region_start_vaddr, region_end_vaddr
        ):
            cb_view = ComplexBlock(cb_start_ea, cb_end_ea - cb_start_ea, cb_name)
            await region_view.create_child_region(cb_view, additional_attributes=(program_attrs,))

        if skip_count > 0:
            LOGGER.warning(
                f"Skipped {skip_count} complex blocks that would have resulted in overlap"
            )

    @staticmethod
    def _binary_ninja_get_complex_blocks(
        binaryview: BinaryView, region_start_vaddr: int, region_end_vaddr: int
    ) -> Iterable[Tuple[int, int, str]]:
        """
        Get virtual address bounds for all complex blocks within the binary

        :param region_start_vaddr:
        :param region_end_vaddr:
        :return: The start virtual address, end virtual address, and name of the function
        """

        # For the function end address, this assumes that functions (complex blocks) reported
        # as the collection of multiple address ranges are coherent/solid and represent an entire
        # function from the start address to the end address. An example where this is observed
        # are x64 functions which contain alignment. BinaryNinja splits the function/cb into a
        # list of address ranges excluding the alignment bytes.
        # A similar assumption is applied in the equivalent IDA analyzer.
        functions = sorted(list(binaryview.functions), key=lambda f: f.start)
        for idx, func in enumerate(functions):
            sorted_address_ranges = sorted(func.address_ranges, key=lambda ar: ar.start)
            contiguous_chunks: List[Tuple[int, int]] = []
            previous_chunk: Optional[Tuple[int, int]] = None
            for address_range in sorted_address_ranges:
                if previous_chunk is None:
                    previous_chunk = address_range.start, address_range.end
                    continue

                chunk_start, chunk_end = previous_chunk

                max_range_start_to_be_contiguous = chunk_end + MAX_GAP_BETWEEN_FUNC_ADDRESS_RANGE

                if address_range.start <= max_range_start_to_be_contiguous:
                    chunk_end = address_range.end
                    previous_chunk = chunk_start, chunk_end
                else:
                    contiguous_chunks.append(previous_chunk)
                    previous_chunk = address_range.start, address_range.end

            if previous_chunk is not None:
                contiguous_chunks.append(previous_chunk)

            chunk_with_entrypoint = None
            for chunk_start, chunk_end in contiguous_chunks:
                if chunk_start <= func.start < chunk_end:
                    chunk_with_entrypoint = chunk_start, chunk_end
                    break

            if chunk_with_entrypoint:
                start_ea, end_ea = chunk_with_entrypoint
                func_code_range = Range(start_ea, end_ea)
            else:
                raise ComplexBlockStructureError(
                    f"No contiguous chunks in "
                    f"{', '.join(f'{hex(c[0])}-{hex(c[1])}' for c in contiguous_chunks)} "
                    f"contained the function start address {hex(func.start)}"
                )
            # Filter functions only within the range [region_start_vaddr, region_end_vaddr].
            if start_ea < region_start_vaddr or end_ea > region_end_vaddr:
                continue
            name = func.name

            # Add literal pools/data by iterating over data word candidates after the function's
            # code boundaries, and checking if there are code references to those candidates from
            # the function's code ranges
            data_refs: List[ReferenceSource] = list()

            # Adjust literal pool start address by accounting alignment "nop" instructions
            while binaryview.get_disassembly(end_ea) == "nop":
                end_ea += binaryview.get_instruction_length(end_ea)

            literal_pool_search_addr = end_ea

            if idx == len(functions) - 1:
                upper_bound = region_end_vaddr
            else:
                upper_bound = functions[idx + 1].start

            while literal_pool_search_addr < upper_bound:
                data_refs.extend(binaryview.get_code_refs(literal_pool_search_addr))
                # Filter out literal pool candidates that not referenced by the code body of the
                # function
                data_refs = [x for x in data_refs if x.address in func_code_range]
                data_var_size = binaryview.get_data_var_at(literal_pool_search_addr)
                if data_refs and data_var_size:
                    literal_pool_search_addr += data_var_size.type.width
                    end_ea = literal_pool_search_addr
                else:
                    literal_pool_search_addr += 1
            yield start_ea, end_ea, name


class BinaryNinjaComplexBlockUnpacker(ComplexBlockUnpacker):
    async def unpack(self, resource: Resource, config: Optional[ComponentConfig] = None):
        cb_view = await resource.view_as(ComplexBlock)
        program_r = await cb_view.resource.get_only_ancestor_as_view(
            Program, ResourceFilter.with_tags(Program)
        )
        program_attrs = await program_r.resource.analyze(ProgramAttributes)
        root_resource = await resource.get_only_ancestor(
            ResourceFilter(tags=[BinaryNinjaAnalysisResource], include_self=True)
        )
        binary_ninja_analysis = await root_resource.analyze(BinaryNinjaAnalysis)
        binaryview = binary_ninja_analysis.binaryview

        cb_data_range = await resource.get_data_range_within_root()
        cb_start_vaddr = cb_view.virtual_address

        binary_ninja_parent_cb = [
            func for func in binaryview.functions if func.start == cb_start_vaddr
        ]
        if len(binary_ninja_parent_cb) == 1:
            binary_ninja_parent_cb = binary_ninja_parent_cb.pop()
        else:
            LOGGER.warning(f"Could not find complex block at {cb_start_vaddr:x} in BinaryNinja")
            return

        bb_children_created = []
        max_code_vaddr = -1

        for bb in binary_ninja_parent_cb.basic_blocks:  # type: ignore
            bb_start_offset = bb.start - cb_start_vaddr + cb_data_range.start
            bb_end_offset = bb.end - cb_start_vaddr + cb_data_range.start
            if bb_end_offset > cb_data_range.end or bb_start_offset < cb_data_range.start:
                warning_string = (
                    f"Basic block {bb.start:#x} does not fall within "
                    f"complex block {cb_view.virtual_address:#x} at "
                    f"offsets {cb_data_range.start:#x}-{cb_data_range.end:#x}"
                )
                warn(RuntimeWarning(warning_string))
                continue

            # VLE not supported by BinaryNinja
            if "thumb" in bb.arch.name:
                mode = InstructionSetMode.THUMB
            else:
                mode = InstructionSetMode.NONE

            is_exit_point = True
            exit_ea = None
            for successor in bb.outgoing_edges:
                is_exit_point = False
                if exit_ea is None or successor.target.start == bb.end:
                    exit_ea = successor.target.start

            bb_view = BasicBlock(
                bb.start,
                bb.length,
                mode,
                is_exit_point,
                exit_ea,
            )
            bb_code_end = bb.start + bb.length
            max_code_vaddr = bb_code_end if bb_code_end > max_code_vaddr else max_code_vaddr

            child_region = cb_view.create_child_region(
                bb_view, additional_attributes=(program_attrs,)
            )
            bb_children_created.append(child_region)

        # Extracted from the ComplexBlockUnpacker, finds literal pools and data by going over all
        # instructions and finding code references.
        LOGGER.debug(f"Getting data words from function {cb_start_vaddr:#x}")

        # Add literal pools/data by iterating over data word candidates after the function's
        # code boundaries, and checking if there are code references to those candidates from
        # the function's code ranges
        literal_pool_search_addr = max_code_vaddr
        # Adjust literal pool start address by accounting alignment "nop" instructions
        while binaryview.get_disassembly(literal_pool_search_addr) == "nop":
            literal_pool_search_addr += binaryview.get_instruction_length(literal_pool_search_addr)

        while literal_pool_search_addr < cb_start_vaddr + cb_view.size:
            data_var: Optional[DataVariable] = binaryview.get_data_var_at(literal_pool_search_addr)
            if data_var is None or data_var.type.width == 0:
                literal_pool_search_addr += 1
                continue

            LOGGER.debug(f"DataWord found at: {data_var.address:#x} of type: {data_var.type}.")
            if data_var.type.type_class in [
                TypeClass.StructureTypeClass,
                TypeClass.ArrayTypeClass,
                TypeClass.EnumerationTypeClass,
            ]:
                LOGGER.debug(f"Potential jump table found at {data_var.address:x}")
                word_size = data_var.type.width // data_var.type.count
            else:
                word_size = data_var.type.width

            for word_vaddr in range(
                data_var.address, data_var.address + data_var.type.width, word_size
            ):
                if word_size == 1:
                    size_flag = "B"
                elif word_size == 2:
                    size_flag = "H"
                elif word_size == 4:
                    size_flag = "L"
                elif word_size == 8:
                    size_flag = "Q"
                else:
                    raise ValueError(f"Bad word size {word_size} at {word_vaddr:x}")

                endian_flag = ">" if binaryview.endianness is Endianness.BigEndian else "<"
                format_string = endian_flag + size_flag
                xrefs = [xref.address for xref in binaryview.get_code_refs(data_var.address)]

                LOGGER.debug(f"Adding DataWord {word_vaddr:#x}")
                bb_children_created.append(
                    cb_view.create_child_region(
                        DataWord(word_vaddr, word_size, format_string, tuple(xrefs))
                    )
                )
            literal_pool_search_addr += data_var.type.width

        await asyncio.gather(*bb_children_created, return_exceptions=True)
