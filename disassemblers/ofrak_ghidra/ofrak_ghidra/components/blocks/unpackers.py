import asyncio
import logging
import os
import re
from collections import defaultdict
from typing import Tuple, List, Dict, Union, Iterable

from ofrak.core.architecture import ProgramAttributes
from ofrak_type.architecture import InstructionSetMode
from ofrak.core.basic_block import BasicBlock
from ofrak.core.code_region import CodeRegionUnpacker, CodeRegion
from ofrak.core.complex_block import ComplexBlock, ComplexBlockUnpacker
from ofrak.core.data import DataWord
from ofrak.resource import Resource, ResourceFactory
from ofrak.service.component_locator_i import ComponentLocatorInterface
from ofrak.service.data_service_i import DataServiceInterface
from ofrak.service.resource_service_i import ResourceFilter, ResourceServiceInterface
from ofrak_ghidra.constants import CORE_OFRAK_GHIDRA_SCRIPTS
from ofrak_ghidra.ghidra_model import GhidraProject, OfrakGhidraMixin, OfrakGhidraScript
from ofrak_ghidra.components.ghidra_analyzer import GhidraCodeRegionModifier
from ofrak_io.batch_manager import make_batch_manager

LOGGER = logging.getLogger(__name__)

RE_STRIP_PRECEDING_ZERO = re.compile(r"0x0+([0-9a-f])")
RE_CPY_TO_MOV = re.compile(r"^cpy")

_GetBasicBlocksRequest = Tuple[Resource, int, int]
_GetBasicBlocksResult = List[Dict[str, Union[str, int, bool]]]
_GetDataWordsRequest = Tuple[Resource, int, int]
_GetDataWordsResult = List[Dict[str, Union[str, int]]]


class GhidraCodeRegionUnpacker(CodeRegionUnpacker, OfrakGhidraMixin):
    get_complex_blocks_script = OfrakGhidraScript(
        os.path.join(CORE_OFRAK_GHIDRA_SCRIPTS, "GetComplexBlocks.java"),
    )

    async def unpack(self, resource: Resource, config=None) -> None:
        # Run the GetCodeRegions script for every CodeRegion to match with the backend.
        # This is not efficient but shouldn't matter much since there shouldn't be too many CodeRegions.
        code_region = await resource.view_as(CodeRegion)
        await resource.run(GhidraCodeRegionModifier)

        code_region_start = code_region.virtual_address
        code_region_end = code_region_start + code_region.size

        program = await resource.get_only_ancestor_as_view(
            GhidraProject, ResourceFilter(tags=[GhidraProject], include_self=True)
        )
        program_attributes = await program.resource.analyze(ProgramAttributes)

        complex_blocks = await self.get_complex_blocks_script.call_script(
            resource,
            hex(code_region_start),
            hex(code_region_end),
        )

        complex_blocks_created = []

        for complex_block in complex_blocks:
            complex_block = ComplexBlock(
                complex_block["loadAddress"], complex_block["size"], complex_block["name"]
            )

            complex_blocks_created.append(
                code_region.create_child_region(
                    complex_block,
                    additional_attributes=(program_attributes,),
                )
            )

        await asyncio.gather(*complex_blocks_created)


class GhidraComplexBlockUnpacker(
    ComplexBlockUnpacker,
    OfrakGhidraMixin,
):
    get_basic_blocks_script = OfrakGhidraScript(
        os.path.join(CORE_OFRAK_GHIDRA_SCRIPTS, "GetBasicBlocks.java")
    )

    get_data_words_script = OfrakGhidraScript(
        os.path.join(CORE_OFRAK_GHIDRA_SCRIPTS, "GetDataWords.java")
    )

    def __init__(
        self,
        resource_factory: ResourceFactory,
        data_service: DataServiceInterface,
        resource_service: ResourceServiceInterface,
        component_locator: ComponentLocatorInterface,
    ):
        self.get_bb_batch_manager = make_batch_manager(self._handle_get_basic_blocks_batch)
        self.get_dw_batch_manager = make_batch_manager(self._handle_get_data_words_batch)
        super().__init__(resource_factory, data_service, resource_service, component_locator)

    async def unpack(self, resource: Resource, config=None):
        cb_view = await resource.view_as(ComplexBlock)

        program_attrs = await resource.analyze(ProgramAttributes)

        cb_data_range = await resource.get_data_range_within_root()
        cb_start_vaddr = cb_view.virtual_address

        children_created = []

        basic_blocks = await self.get_bb_batch_manager.get_result(
            (resource, cb_data_range.start, cb_start_vaddr)
        )

        for bb_info in basic_blocks:
            bb_start_vaddr = bb_info["bb_start_vaddr"]
            bb_size = bb_info["bb_size"]
            is_exit_point = bb_info["is_exit_point"]
            mode_string = bb_info["instr_mode"]
            exit_vaddr = bb_info["exit_vaddr"]
            # The Ghidra script initializes exit_vaddr to -1. If is_exit_point, we want exit_vaddr
            # to be None; this is consistent with the docstring of BasicBlock
            if is_exit_point:
                exit_vaddr = None

            if bb_size == 0:
                raise Exception(f"Basic block 0x{bb_start_vaddr:x} has no size")

            if (
                bb_start_vaddr < cb_view.virtual_address
                or (bb_start_vaddr + bb_size) > cb_view.end_vaddr()
            ):
                logging.warning(
                    f"Basic Block 0x{bb_start_vaddr:x} does not fall within "
                    f"complex block {hex(cb_view.virtual_address)}-{hex(cb_view.end_vaddr())}"
                )
                continue

            mode = InstructionSetMode[mode_string]

            bb_view = BasicBlock(
                bb_start_vaddr,
                bb_size,
                mode,
                is_exit_point,
                exit_vaddr,
            )

            children_created.append(
                cb_view.create_child_region(bb_view, additional_attributes=(program_attrs,))
            )

        data_words = await self.get_dw_batch_manager.get_result(
            (resource, cb_view.virtual_address, cb_view.end_vaddr())
        )

        for data_word_info in data_words:
            word_vaddr = data_word_info["word_vaddr"]
            word_size = data_word_info["word_size"]
            xrefs = [xref for xref in data_word_info["xrefs"]]

            if (
                word_vaddr < cb_view.virtual_address
                or (word_vaddr + word_size) > cb_view.end_vaddr()
            ):
                logging.warning(
                    f"Data Word 0x{word_vaddr:x} does not fall within "
                    f"complex block {hex(cb_view.virtual_address)}-{hex(cb_view.end_vaddr())}"
                )
                continue

            num_words = 1
            if word_size == 1:
                size_flag = "B"
            elif word_size == 2:
                size_flag = "H"
            elif word_size == 4:
                size_flag = "L"
            elif word_size == 8:
                size_flag = "Q"
            else:
                size_flag = "B"
                num_words = word_size
                word_size = 1

            format_string = program_attrs.endianness.get_struct_flag() + size_flag

            for word in range(num_words):
                dw_view = DataWord(
                    word_vaddr + word,
                    word_size,
                    format_string,
                    tuple(xrefs),
                )

                children_created.append(
                    cb_view.create_child_region(
                        dw_view,
                        additional_attributes=(program_attrs,),
                    )
                )

        await asyncio.gather(*children_created)

    async def _handle_get_basic_blocks_batch(
        self, requests: Tuple[_GetBasicBlocksRequest, ...]
    ) -> Iterable[Tuple[_GetBasicBlocksRequest, _GetBasicBlocksResult]]:
        requests_by_resource = defaultdict(list)
        resources_by_id = dict()
        for req in requests:
            resource, _, _ = req
            ghidra_project = await self.get_ghidra_project(resource)
            requests_by_resource[ghidra_project.resource.get_id()].append(req)
            resources_by_id[ghidra_project.resource.get_id()] = resource

        all_results = []

        for resource_id, requests in requests_by_resource.items():
            resource = resources_by_id[resource_id]
            start_offsets = ",".join(hex(start_offset) for _, start_offset, _ in requests)
            start_vaddrs = ",".join(hex(start_vaddr) for _, _, start_vaddr in requests)

            results = await self.get_basic_blocks_script.call_script(
                resource,
                start_offsets,
                start_vaddrs,
            )

            all_results.extend(zip(requests, results))

        return all_results

    async def _handle_get_data_words_batch(
        self, requests: Tuple[_GetBasicBlocksRequest, ...]
    ) -> Iterable[Tuple[_GetBasicBlocksRequest, _GetBasicBlocksResult]]:
        requests_by_resource = defaultdict(list)
        resources_by_id = dict()
        for req in requests:
            resource, _, _ = req
            ghidra_project = await self.get_ghidra_project(resource)
            requests_by_resource[ghidra_project.resource.get_id()].append(req)
            resources_by_id[ghidra_project.resource.get_id()] = resource

        all_results = []

        for resource_id, requests in requests_by_resource.items():
            resource = resources_by_id[resource_id]
            function_start_vaddrs = ",".join(
                hex(function_start_vaddr) for _, function_start_vaddr, _ in requests
            )
            function_end_vaddrs = ",".join(
                hex(function_end_vaddr) for _, _, function_end_vaddr in requests
            )

            results = await self.get_data_words_script.call_script(
                resource,
                function_start_vaddrs,
                function_end_vaddrs,
            )

            all_results.extend(zip(requests, results))

        return all_results
