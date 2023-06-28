import asyncio
import os
import re
from collections import defaultdict
from typing import Tuple, Dict, Union, List, Iterable

from ofrak.core.architecture import ProgramAttributes
from ofrak_type.architecture import InstructionSet, InstructionSetMode, SubInstructionSet
from ofrak.core.basic_block import BasicBlockUnpacker, BasicBlock
from ofrak.core.instruction import Instruction
from ofrak.resource import ResourceFactory, Resource
from ofrak.service.component_locator_i import ComponentLocatorInterface
from ofrak.service.data_service_i import DataServiceInterface
from ofrak.service.resource_service_i import ResourceServiceInterface
from ofrak_ghidra.components.blocks.unpackers import (
    RE_STRIP_PRECEDING_ZERO,
    RE_CPY_TO_MOV,
)
from ofrak_ghidra.constants import CORE_OFRAK_GHIDRA_SCRIPTS
from ofrak_ghidra.ghidra_model import OfrakGhidraMixin, OfrakGhidraScript
from ofrak_io.batch_manager import make_batch_manager

_GetInstructionsRequest = Tuple[Resource, int, int]
_GetInstructionsResult = List[Dict[str, Union[str, int]]]


class GhidraBasicBlockUnpacker(
    BasicBlockUnpacker,
    OfrakGhidraMixin,
):
    rate_limit = 1
    id = b"GhidraBasicBlockUnpacker"

    get_instructions_script = OfrakGhidraScript(
        os.path.join(CORE_OFRAK_GHIDRA_SCRIPTS, "GetInstructions.java"),
    )

    def __init__(
        self,
        resource_factory: ResourceFactory,
        data_service: DataServiceInterface,
        resource_service: ResourceServiceInterface,
        component_locator: ComponentLocatorInterface,
    ):
        self.batch_manager = make_batch_manager(self._handle_get_instructions_batch)
        super().__init__(resource_factory, data_service, resource_service, component_locator)

    async def unpack(self, resource: Resource, config=None):
        bb_view: BasicBlock = await resource.view_as(BasicBlock)
        bb_start_vaddr = bb_view.virtual_address
        instructions = await self.batch_manager.get_result(
            (
                resource,
                bb_start_vaddr,
                bb_start_vaddr + bb_view.size - 1,  # Ghidra is inclusive
            ),
        )
        program_attrs = await resource.analyze(ProgramAttributes)

        children_created = []
        for instruction in instructions:
            vaddr = instruction["instr_offset"]
            size = instruction["instr_size"]
            mnem, operands = _asm_fixups(
                instruction["mnem"].lower(), instruction["operands"].lower(), program_attrs
            )
            results = instruction["results"].split(",")
            regs_read = list()
            regs_written = list()
            # TODO A way to standardize register representations
            if all(item in results for item in ["CF", "PF", "ZF", "SF", "OF"]):
                regs_written.append("rflags")
            if all(item in results for item in ["RSP"]):
                regs_written.append("rsp")
                regs_read.append("rsp")

            for reg in instruction["regs_read"].lower().split(","):
                if reg not in regs_read and reg != "":
                    regs_read.append(reg)
            for reg in instruction["regs_written"].lower().split(","):
                if reg not in regs_written and reg != "":
                    regs_written.append(reg)
            disasm = f"{mnem} {operands}"

            mode_string = instruction.get("instr_mode", "NONE")
            mode = InstructionSetMode[mode_string]
            assert mode == bb_view.mode, (
                f"The instruction mode {mode.name} returned by Ghidra does not match the basic "
                f"block mode {bb_view.mode.name}."
            )

            instruction = Instruction(
                virtual_address=vaddr,
                size=size,
                disassembly=disasm,
                mnemonic=mnem,
                operands=operands,
                mode=mode,
            )
            children_created.append(
                bb_view.create_child_region(instruction, additional_attributes=(program_attrs,))
            )
        await asyncio.gather(*children_created)

    async def _handle_get_instructions_batch(
        self, requests: Tuple[_GetInstructionsRequest, ...]
    ) -> Iterable[Tuple[_GetInstructionsRequest, _GetInstructionsResult]]:
        requests_by_resource = defaultdict(list)
        ghidra_project_resources_by_id = dict()
        for req in requests:
            resource, _, _ = req
            ghidra_project = await self.get_ghidra_project(resource)
            requests_by_resource[ghidra_project.resource.get_id()].append(req)
            ghidra_project_resources_by_id[ghidra_project.resource.get_id()] = resource

        all_results = []

        for resource_id, requests in requests_by_resource.items():
            resource = ghidra_project_resources_by_id[resource_id]
            bb_starts = ",".join(hex(bb_start) for _, bb_start, _ in requests)
            bb_ends = ",".join(hex(bb_end) for _, _, bb_end in requests)

            results = await self.get_instructions_script.call_script(resource, bb_starts, bb_ends)

            all_results.extend(zip(requests, results))

        return all_results


def _asm_fixups(
    base_mnemonic: str, base_operands: str, program_attrs: ProgramAttributes
) -> Tuple[str, str]:
    """
    Fix up an assembly instruction from Ghidra, so that the toolchain can assemble it.

    :param base_mnemonic: original mnemonic from Ghidra
    :param base_operands: original operands from Ghidra
    :param program_attrs: ProgramAttributes for the binary analyzed in Ghidra

    :return: fixed up assembly instruction
    """
    operands = base_operands.replace(",", ", ")
    operands = operands.replace("+ -", "- ")
    operands = re.sub(RE_STRIP_PRECEDING_ZERO, r"0x\1", operands)
    if program_attrs.isa is InstructionSet.ARM:
        # Convert the CPY Ghidra instruction to the more commonly used MOV instruction
        mnemonic = re.sub(RE_CPY_TO_MOV, "mov", base_mnemonic)
    elif program_attrs.isa is InstructionSet.M68K:
        # Convert the Ghidra assembly syntax (that corresponds to the manual's syntax) to AT&T syntax that the GNU toolchain uses
        mnemonic = base_mnemonic
        operands = operands.replace("sp", "%SP")
        operands = operands.replace("sr", "%SR")
        operands = operands.replace(" 0x", " #0x")
        operands = operands.replace(" -0x", " #-0x")
        for mnem in [
            "moveq",
            "mov3q",
            "subq",
            "cmpi",
            "addq",
            "cmpi",
            "addi",
            "ori",
            "subi",
            "stop",
        ]:
            if mnem in mnemonic:
                operands = re.sub(r"^0x", r"#0x", operands)

        operand_list = re.split("(,)", operands)
        operands = ""
        for operand in operand_list:
            if not "0x" in operand:
                operand = re.sub(r"a([0-7])", r"%A\1", operand)
                operand = re.sub(r"d([0-7])[bw]?", r"%D\1", operand)
            operands += operand
    elif program_attrs.sub_isa is SubInstructionSet.PPCVLE:
        # in Ghidra, offsets from a register like in `se_stw     r0,0x9(r1)` are expressed in words.
        # so in this example r0 is stored at r1+0x9*4=r1+0x24
        # But it is more natural to express it in bytes, to get the instruction `se_stw r0,0x24(r1)`
        # (this is also the convention used by the VLE assembler)

        mnemonic = base_mnemonic
        operands = re.sub(
            r"(.*, )(0x[0-9]+)(\(r[0-9]+\))",
            lambda match: match.group(1) + f"0x{int(match.group(2), 0)*4:x}" + match.group(3),
            operands,
        )
    else:
        mnemonic = base_mnemonic
    return mnemonic, operands
