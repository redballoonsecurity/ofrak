import asyncio
import logging


import pyghidra
from ofrak.core import *
from tempfile import TemporaryDirectory
import os
import re


from ofrak.core.code_region import CodeRegion
from ofrak.core.complex_block import ComplexBlock

_GHIDRA_AUTO_LOADABLE_FORMATS = [Elf, Ihex, Pe]


def _parse_offset(java_object):
    """
    This parses the offset as a big int
    """
    return int(str(java_object.getOffsetAsBigInteger()))


@dataclass
class PyGhidraAutoLoadProject(ResourceView):
    pass


class PyGhidraAnalysisIdentifier(Identifier):
    """
    Component to identify resources to analyze with Ghidra. If this component is discovered,
    it will tag all [Program][ofrak.core.program.Program]s as GhidraProjects
    """

    id = b"GhidraAnalysisIdentifier"
    targets = (Program,)

    async def identify(self, resource: Resource, config=None):
        for tag in _GHIDRA_AUTO_LOADABLE_FORMATS:
            if resource.has_tag(tag):
                resource.add_tag(PyGhidraAutoLoadProject)


@dataclass
class PyGhidraUnpackerConfig(ComponentConfig):
    unpack_complex_blocks: bool


class PyGhidraUnpacker(Unpacker[None]):
    id = b"PyGhidraUnpacker"

    targets = (PyGhidraAutoLoadProject,)
    children = (ComplexBlock, BasicBlock, DataWord, Instruction)

    async def unpack(self, resource: Resource, config: Optional[PyGhidraUnpackerConfig] = None):
        if config is not None:
            unpack_bbs = config.unpack_complex_blocks
        else:
            unpack_bbs = True
        await resource.auto_run(all_unpackers=True, blacklisted_components=(PyGhidraUnpacker,))
        program_attributes = await resource.analyze(ProgramAttributes)
        with TemporaryDirectory() as tempdir:
            program_file = os.path.join(tempdir, "program")
            await resource.flush_data_to_disk(program_file)
            with pyghidra.open_program(program_file) as flat_api:
                from ghidra.program.model.block import BasicBlockModel

                ofrak_code_regions = await self.unpack_program(resource, flat_api)
                for code_region in ofrak_code_regions:
                    func_cbs = await self.unpack_code_region(
                        code_region, program_attributes, flat_api
                    )
                    for func, cb in func_cbs:
                        cb_resource = await code_region.create_child_region(cb)
                        cb_view = await cb_resource.view_as(ComplexBlock)
                        if not unpack_bbs:
                            continue
                        bb_model = BasicBlockModel(flat_api.getCurrentProgram())
                        basic_blocks, data_words = await self.unpack_complex_block(
                            cb_resource, func, program_attributes, bb_model, flat_api
                        )
                        for block, bb in basic_blocks:
                            if bb.size == 0:
                                raise Exception(f"Basic block 0x{bb.virtual_address:x} has no size")

                            if (
                                bb.virtual_address < cb_view.virtual_address
                                or (bb.virtual_address + bb.size) > cb_view.end_vaddr()
                            ):
                                logging.warning(
                                    f"Basic Block 0x{bb.virtual_address:x} does not fall within "
                                    f"complex block {hex(cb_view.virtual_address)}-{hex(cb_view.end_vaddr())}"
                                )
                                continue
                            bb_resource = await cb_view.create_child_region(bb)
                            bb_view = await bb_resource.view_as(BasicBlock)
                            instructions = await self.unpack_basic_block(block, flat_api)
                            for instruction in instructions:
                                await bb_view.create_child_region(instruction)

                        for dw in data_words:
                            if (
                                dw.virtual_address < cb_view.virtual_address
                                or (dw.virtual_address + dw.size) > cb_view.end_vaddr()
                            ):
                                logging.warning(
                                    f"Data Word 0x{dw.virtual_address:x} does not fall within "
                                    f"complex block {hex(cb_view.virtual_address)}-{hex(cb_view.end_vaddr())}"
                                )
                                continue
                            await cb_view.create_child_region(dw)

    async def unpack_program(self, resource, flat_api):
        ofrak_code_regions = await resource.get_descendants_as_view(
            v_type=CodeRegion,
            r_filter=ResourceFilter(include_self=True, tags=(CodeRegion,)),
        )
        ghidra_code_regions = list()
        for memory_block in flat_api.getMemoryBlocks():
            if memory_block.isExecute():
                ghidra_code_regions.append(
                    CodeRegion(
                        _parse_offset(memory_block.getStart()),
                        size=memory_block.getSize(),
                    )
                )

        ofrak_code_regions = sorted(ofrak_code_regions, key=lambda cr: cr.virtual_address)
        backend_code_regions = sorted(ghidra_code_regions, key=lambda cr: cr.virtual_address)

        for code_region in ofrak_code_regions:
            relative_va = code_region.virtual_address - ofrak_code_regions[0].virtual_address

            for backend_code_region in backend_code_regions:
                backend_relative_va = (
                    backend_code_region.virtual_address - backend_code_regions[0].virtual_address
                )
                if (
                    backend_relative_va == relative_va
                    and backend_code_region.size == code_region.size
                ):
                    code_region.virtual_address = backend_code_region.virtual_address
                    break
        await asyncio.gather(*[code_region.resource.save() for code_region in ofrak_code_regions])
        return ofrak_code_regions

    async def unpack_code_region(self, code_region: CodeRegion, program_attributes, flat_api):
        functions = []
        start_address = (
            flat_api.getAddressFactory()
            .getDefaultAddressSpace()
            .getAddress(hex(code_region.virtual_address))
        )
        end_address = (
            flat_api.getAddressFactory()
            .getDefaultAddressSpace()
            .getAddress(hex(code_region.virtual_address + code_region.size))
        )
        func = flat_api.getFunctionAt(start_address)
        if func is None:
            func = flat_api.getFunctionAfter(start_address)
            if func is None:
                return

        while func is not None and end_address.subtract(func.getEntryPoint()) > 0:
            virtual_address = _parse_offset(func.getEntryPoint())
            start = _parse_offset(func.getEntryPoint())
            end, _ = self.get_last_address(func, flat_api)
            if end is not None:
                cb = ComplexBlock(
                    virtual_address=virtual_address,
                    size=end - start,
                    name=func.getName(),
                )
                functions.append((func, cb))
            func = flat_api.getFunctionAfter(func)
        return functions

    async def unpack_complex_block(
        self, resource: Resource, func, program_attributes, bb_model, flat_api
    ) -> Tuple[any, BasicBlock]:
        bbs = []
        bb_iter = bb_model.getCodeBlocksContaining(func.getBody(), flat_api.monitor)
        for block in bb_iter:
            address_range = block.getAddressRanges().next()
            start = _parse_offset(address_range.getMinAddress())
            size = address_range.getLength()
            exit_vaddr = None
            is_exit_point = True
            iterator = block.getDestinations(flat_api.monitor)
            ghidra_block = block
            while block is not None:
                block = iterator.next()
                if block is None:
                    break
                successor_bb = block.getDestinationBlock()
                successor_bb_address_range = successor_bb.getAddressRanges().next()
                if _parse_offset(successor_bb_address_range.getMinAddress()) >= _parse_offset(
                    func.getBody().getMinAddress()
                ) and _parse_offset(successor_bb_address_range.getMaxAddress()) <= _parse_offset(
                    func.getBody().getMaxAddress()
                ):
                    is_exit_point = False
                    if (
                        exit_vaddr is None
                        or _parse_offset(successor_bb_address_range.getMinAddress())
                        == _parse_offset(address_range.getMaxAddress()) + 1
                    ):
                        exit_vaddr = _parse_offset(successor_bb_address_range.getMinAddress())
            from java.math import BigInteger

            instruction_mode = InstructionSetMode.NONE
            if program_attributes.isa == InstructionSet.ARM:
                tmode_register = flat_api.getCurrentProgram().getRegister("TMode")
                function_mode = (
                    flat_api.getCurrentProgram()
                    .getProgramContext()
                    .getRegisterValue(tmode_register, address_range.getMinAddress())
                )
                if function_mode.getUnsignedValueIgnoreMask().equals(BigInteger.ONE):
                    instruction_mode = InstructionSetMode.THUMB
            elif program_attributes.isa == InstructionSet.PPC:
                vle_register = flat_api.getCurrentProgram().getRegister("vle")
                function_mode = (
                    flat_api.getCurrentProgram()
                    .getProgramContext()
                    .getRegisterValue(vle_register, address_range.getMinAddress())
                )
                if function_mode.getUnsignedValueIgnoreMask().equals(BigInteger.ONE):
                    instruction_mode = InstructionSetMode.VLE

                if bb.is_exit_point:
                    exit_vaddr = None

            bb = BasicBlock(
                virtual_address=start,
                size=size,
                mode=instruction_mode,
                is_exit_point=is_exit_point,
                exit_vaddr=exit_vaddr,
            )
            bbs.append((ghidra_block, bb))

        end_data_addr, end_code_addr = self.get_last_address(func, flat_api)

        dws = []
        data = flat_api.getDataAt(end_code_addr)
        while data is not None and _parse_offset(data.getAddress()) <= end_data_addr:
            num_words = 1
            word_size = data.getLength()
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

            format_string = program_attributes.endianness.get_struct_flag() + size_flag

            refs = [
                _parse_offset(ref.getFromAddress())
                for ref in flat_api.getReferencesTo(data.getAddress())
            ]
            for word in range(num_words):
                dws.append(
                    DataWord(
                        virtual_address=_parse_offset(data.getAddress()) + word,
                        size=data.getLength(),
                        format_string=format_string,
                        xrefs_to=tuple(refs),
                    )
                )
            data = flat_api.getDataAfter(data)

        return bbs, dws

    async def unpack_basic_block(self, block, flat_api):
        from java.math import BigInteger
        from ghidra.program.model.symbol import RefType

        instructions = []
        address_range = block.getAddressRanges().next()
        start = _parse_offset(address_range.getMinAddress())
        size = int(address_range.getLength())
        end = start + size
        instr = flat_api.getInstructionAt(address_range.getMinAddress())
        while instr is not None and _parse_offset(instr.getAddress()) < end:
            res = []
            ops = []
            regs_read = []
            regs_written = []
            results_objects = instr.getResultObjects()
            instr_offset = instr.getAddress()
            instr_size = instr.getLength()
            mnem = instr.getMnemonicString()

            thumb_register = instr.getRegister("TMode")
            instruction_mode = InstructionSetMode.NONE
            if thumb_register is not None:
                thumb_val = instr.getValue(thumb_register, False)
                if thumb_val.equals(BigInteger.ONE):
                    instruction_mode = InstructionSetMode.THUMB
            else:
                vle_register = instr.getRegister("vle")
                if vle_register is not None:
                    vle_val = instr.getValue(vle_register, False)
                    if vle_val.equals(BigInteger.ONE):
                        instruction_mode = InstructionSetMode.VLE
            for i in range(int(instr.getNumOperands())):
                ops.append(instr.getDefaultOperandRepresentation(i))
                if i != instr.getNumOperands() - 1:
                    ops.append(", ")
                if instr.getOperandRefType(i) == RefType.READ:
                    regs_read.append(
                        instr.getOpObjects(i)[instr.getOpObjects(i).length - 1].toString()
                    )
                    if i != instr.getNumOperands() - 1:
                        regs_read.append(", ")

                if instr.getOperandRefType(i) == RefType.WRITE:
                    regs_written.append(
                        instr.getOpObjects(i)[instr.getOpObjects(i).length - 1].toString()
                    )
                    if i != instr.getNumOperands() - 1:
                        regs_written.append(", ")

                if instr.getOperandRefType(i) == RefType.READ_WRITE:
                    regs_read.append(
                        instr.getOpObjects(i)[instr.getOpObjects(i).length - 1].toString()
                    )
                    regs_written.append(
                        instr.getOpObjects(i)[instr.getOpObjects(i).length - 1].toString()
                    )
                    if i != instr.getNumOperands() - 1:
                        regs_read.append(", ")
                        regs_written.append(", ")
            results_objects = instr.getResultObjects()
            for i in range(len(results_objects)):
                res.append(results_objects[i])
                if i != len(results_objects) - 1:
                    res.append(", ")
            vaddr = _parse_offset(instr_offset)
            size = int(instr_size)
            ops = [op.lower() for op in ops]
            operands = "".join(ops)
            mnem = str(mnem).lower()
            mnem = re.sub("cpy", "mov", mnem)
            operands = re.sub("0x[0]+([0-9])", lambda match: f"0x{match.group(1)}", operands)
            operands = re.sub(" \+ -", " - ", operands)
            operands = re.sub(",([^\s])", lambda match: f", {match.group(1)}", operands)
            disasm = f"{mnem} {operands}"
            instructions.append(
                Instruction(
                    virtual_address=vaddr,
                    size=size,
                    disassembly=disasm,
                    mnemonic=mnem,
                    operands=operands,
                    mode=instruction_mode,
                )
            )
            instr = flat_api.getInstructionAfter(instr_offset)
        return instructions

    def get_last_address(self, func, flat_api):
        end_addr = None
        address_iter = func.getBody().getAddressRanges()
        nextFunc = flat_api.getFunctionAfter(func)
        if nextFunc is None:
            nextFuncAddr = func.getBody().getMaxAddress()
        else:
            nextFuncAddr = nextFunc.getEntryPoint()

        while address_iter.hasNext():
            range = address_iter.next()
            if range.getMaxAddress().subtract(nextFuncAddr) > 0:
                break
            end_addr = range.getMaxAddress()
        last_insn = flat_api.getInstructionAt(end_addr)
        if last_insn is None:
            last_insn = flat_api.getInstructionBefore(end_addr)
        if last_insn is None:
            end_addr = end_addr.add(1)
        elif func.equals(flat_api.getFunctionContaining(last_insn.getAddress())):
            end_addr = last_insn.getAddress().add(last_insn.getLength())
        end_code_addr = end_addr
        data = flat_api.getDataAt(end_addr)
        while data is not None and nextFuncAddr.subtract(data.getAddress()) > 0:
            end_addr = data.getAddress().add(data.getLength())
            data = flat_api.getDataAfter(data)
        return _parse_offset(end_addr), end_code_addr


class PyGhidraCodeRegionUnpacker(Unpacker[None]):
    id = b"PyGhidraCodeRegionUnpacker"

    targets = (PyGhidraAutoLoadProject,)
    children = (ComplexBlock,)

    async def unpack(self, resource: Resource, config=None):
        await resource.run(
            PyGhidraUnpacker, config=PyGhidraUnpackerConfig(unpack_complex_blocks=False)
        )
