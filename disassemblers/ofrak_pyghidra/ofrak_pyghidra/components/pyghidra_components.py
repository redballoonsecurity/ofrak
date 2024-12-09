import pyghidra
from ofrak.core import *
from tempfile import TemporaryDirectory
import os


_GHIDRA_AUTO_LOADABLE_FORMATS = [Elf, Ihex, Pe]


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


class PyGhidraUnpacker(Unpacker[None]):
    id = b"PyGhidraUnpacker"

    targets = (PyGhidraAutoLoadProject,)
    children = (ComplexBlock, BasicBlock, Instruction)

    async def unpack(self, resource: Resource, config=None):
        program_attributes = await resource.analyze(ProgramAttributes)
        with TemporaryDirectory() as tempdir:
            program_file = os.path.join(tempdir, "program")
            await resource.flush_data_to_disk(program_file)
            with pyghidra.open_program(program_file) as flat_api:
                from ghidra.program.model.block import BasicBlockModel

                cbs = await self.get_cbs(resource, flat_api)
                bb_model = BasicBlockModel(flat_api.getCurrentProgram())
                for func, cb in cbs:
                    cb_resource = await resource.create_child_from_view(view=cb)
                    basic_blocks = await self.get_bbs(resource, func, bb_model, flat_api)

    async def get_cbs(self, resource: Resource, flat_api):
        functions = []
        func = flat_api.getFirstFunction()
        end = self.addr_to_int(func.getEntryPoint()) + await resource.get_data_length()
        while func is not None and self.addr_to_int(func.getEntryPoint()) < end:
            if func is not None:
                virtual_address = func.getEntryPoint().getOffset()
                end = self.addr_to_int(self.get_last_address(func, flat_api))
                if end is not None:
                    cb = ComplexBlock(
                        virtual_address=virtual_address,
                        size=end - self.addr_to_int(func.getEntryPoint()),
                        name=func.getName(),
                    )
                    functions.append((func, cb))
            func = flat_api.getFunctionAfter(func)
        return functions

    async def get_bbs(self, resource: Resource, func, bb_model, flat_api):
        bbs = []
        bb_iter = bb_model.getCodeBlocksContaining(func.getBody(), flat_api.monitor)
        for block in bb_iter:
            address_range = block.getAddressRanges().next()
            start = address_range.getMinAddress().getOffset()
            size = address_range.getLength()
            exit_vaddr = -1
            is_exit_point = True
            iterator = block.getDestinations(flat_api.monitor)
            while block is not None:
                block = iterator.next()
                if block is None:
                    break
                successor_bb = block.getDestinationBlock()
                successor_bb_address_range = successor_bb.getAddressRanges().next()
                if (
                    successor_bb_address_range.getMinAddress().getOffset()
                    >= func.getBody().getMinAddress().getOffset()
                    and successor_bb_address_range.getMaxAddress().getOffset()
                    <= func.getBody().getMaxAddress().getOffset()
                ):
                    is_exit_point = False
                    if (
                        exit_vaddr == -1
                        or successor_bb_address_range.getMinAddress().getOffset()
                        == address_range.getMaxAddress().getOffset() + 1
                    ):
                        exit_vaddr = successor_bb_address_range.getMinAddress().getOffset()
            elf = await resource.view_as(Elf)
            program_attributes = await resource.analyze(ProgramAttributes)
            instruction_mode = None
            if program_attributes.isa == InstructionSet.ARM:
                tmode_register = flat_api.getCurrentProgram().getRegister("TMode")
                function_mode = (
                    flat_api.getCurrentProgram()
                    .getProgramContext()
                    .getRegisterValue(tmode_register, address_range.getMinAddress())
                )
                if function_mode.getUnsignedValueIgnoreMask() == 1:
                    instruction_mode = InstructionSetMode.THUMB
            elif program_attributes.isa == InstructionSet.PPC:
                vle_register = flat_api.getCurrentProgram().getRegister("vle")
                function_mode = (
                    flat_api.getCurrentProgram()
                    .getProgramContext()
                    .getRegisterValue(vle_register, address_range.getMinAddress())
                )
                if function_mode.getUnsignedValueIgnoreMask() == 1:
                    instruction_mode = InstructionSetMode.VLE
            bb = BasicBlock(
                virtual_address=start,
                size=size,
                mode=instruction_mode,
                is_exit_point=is_exit_point,
                exit_vaddr=exit_vaddr,
            )
            bbs.append((block, bb))
        return bbs

    def addr_to_int(self, addr):
        if addr == None:
            return None
        return int(addr.toString(), 16)

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
        return end_addr
