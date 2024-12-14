import pyghidra
from ofrak.core import *
import struct
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


@dataclass
class PyGhidraUnpackerConfig(ComponentConfig):
    unpack_complex_blocks: bool


class PyGhidraUnpacker(Unpacker[None]):
    id = b"PyGhidraUnpacker"

    targets = (PyGhidraAutoLoadProject,)
    children = (ComplexBlock, BasicBlock, DataWord)

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

                cbs = await self.unpack_code_region(resource, program_attributes, flat_api)
                bb_model = BasicBlockModel(flat_api.getCurrentProgram())
                await self.get_code_regions(resource, flat_api)
                code_regions = await resource.get_descendants_as_view(
                    v_type=CodeRegion,
                    r_filter=ResourceFilter(include_self=True, tags=(CodeRegion,)),
                )
                for func, cb in cbs:
                    for code_region in code_regions:
                        if code_region.contains(cb.virtual_address):
                            cr = code_region
                            break
                        else:
                            cr = None
                    if cr is None:
                        continue
                    cb_resource = await cr.create_child_region(cb)
                    basic_blocks, data_words = await self.unpack_complex_block(
                        resource, func, program_attributes, bb_model, flat_api
                    )
                    cb_view = await cb_resource.view_as(ComplexBlock)
                    if not unpack_bbs:
                        continue
                    for block, bb in basic_blocks:
                        if bb.is_exit_point:
                            exit_vaddr = None

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
                        await cb_view.create_child_region(bb)
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

    async def get_code_regions(self, resource: Resource, flat_api):
        backend_code_regions = []
        blocks = flat_api.getMemoryBlocks()
        for block in blocks:
            if block.isExecute():
                virtual_address = self.addr_to_int(block.start)
                cr = CodeRegion(virtual_address=virtual_address, size=block.getSize())
                backend_code_regions.append(cr)
        ofrak_code_regions = await resource.get_descendants_as_view(
            v_type=CodeRegion, r_filter=ResourceFilter(tags=[CodeRegion])
        )
        ofrak_code_regions = sorted(ofrak_code_regions, key=lambda cr: cr.virtual_address)
        backend_code_regions = sorted(backend_code_regions, key=lambda cr: cr.virtual_address)
        if len(ofrak_code_regions) > 0:
            code_region = ofrak_code_regions[0]
            relative_va = code_region.virtual_address - ofrak_code_regions[0].virtual_address

            for backend_cr in backend_code_regions:
                backend_relative_va = (
                    backend_cr.virtual_address - backend_code_regions[0].virtual_address
                )

                if backend_relative_va == relative_va and backend_cr.size == code_region.size:
                    resource.add_view(backend_cr)
                    return

            LOGGER.debug(
                f"No code region with relative offset {relative_va} and size {code_region.size} found in Ghidra"
            )
        else:
            LOGGER.debug("No OFRAK code regions to match in Ghidra")
        return

    async def unpack_code_region(self, resource: Resource, program_attributes, flat_api):
        functions = []
        func = flat_api.getFirstFunction()
        while func is not None:
            virtual_address = func.getEntryPoint().getOffset()
            start = self.addr_to_int(func.getEntryPoint())
            end, _ = self.get_last_address(func, flat_api)
            try:
                end = self.addr_to_int(end)
            except:
                import ipdb

                ipdb.set_trace()
            if program_attributes.bit_width == BitWidth.BIT_64:
                mask = 0xFFFFFFFFFFFFFFFF
            else:
                mask = 0xFFFFFFFF
            if virtual_address < 0:
                virtual_address = abs((virtual_address ^ mask) + 1)
            if end < 0:
                end = abs((end ^ mask) + 1)
            if start < 0:
                start = abs((end ^ mask) + 1)

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
            start = address_range.getMinAddress().getOffset()
            size = address_range.getLength()
            exit_vaddr = None
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
                        exit_vaddr is None
                        or successor_bb_address_range.getMinAddress().getOffset()
                        == address_range.getMaxAddress().getOffset() + 1
                    ):
                        exit_vaddr = successor_bb_address_range.getMinAddress().getOffset()
            instruction_mode = InstructionSetMode.NONE
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

            if program_attributes.bit_width == BitWidth.BIT_64:
                mask = 0xFFFFFFFFFFFFFFFF
            else:
                mask = 0xFFFFFFFF
            if start < 0:
                start = abs((start ^ mask) + 1)
            if exit_vaddr is not None and exit_vaddr < 0:
                exit_vaddr = abs((exit_vaddr ^ mask) + 1)

            bb = BasicBlock(
                virtual_address=start,
                size=size,
                mode=instruction_mode,
                is_exit_point=is_exit_point,
                exit_vaddr=exit_vaddr,
            )
            bbs.append((block, bb))

        end_data_addr, end_code_addr = self.get_last_address(func, flat_api)

        dws = []
        data = flat_api.getDataAt(end_code_addr)
        while data is not None and data.getAddress() <= end_data_addr:
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
                self.addr_to_int(ref.getFromAddress())
                for ref in flat_api.getReferencesTo(data.getAddress())
            ]
            for word in range(num_words):
                dws.append(
                    DataWord(
                        virtual_address=self.addr_to_int(data.getAddress()) + word,
                        size=data.getLength(),
                        format_string=format_string,
                        xrefs_to=tuple(refs),
                    )
                )
            data = flat_api.getDataAfter(data)

        return bbs, dws

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
        end_code_addr = end_addr
        data = flat_api.getDataAt(end_addr)
        while data is not None and nextFuncAddr.subtract(data.getAddress()) > 0:
            end_addr = data.getAddress().add(data.getLength())
            data = flat_api.getDataAfter(data)
        return end_addr, end_code_addr


class PyGhidraCodeRegionUnpacker(Unpacker[None]):
    id = b"PyGhidraCodeRegionUnpacker"

    targets = (PyGhidraAutoLoadProject,)
    children = (ComplexBlock,)

    async def unpack(self, resource: Resource, config=None):
        await resource.run(
            PyGhidraUnpacker, config=PyGhidraUnpackerConfig(unpack_complex_blocks=False)
        )
