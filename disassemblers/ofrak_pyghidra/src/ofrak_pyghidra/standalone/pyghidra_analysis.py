import logging
import os
import hashlib
import traceback
from typing import Any, Dict, Optional, Union, List

import pyghidra
import argparse
import time
import re
import json
from tempfile312 import mkdtemp
from tqdm import tqdm

from ofrak_type.memory_permissions import MemoryPermissions

LOGGER = logging.getLogger("ofrak_pyghidra")


class PyGhidraComponentException(Exception):
    pass


def _parse_offset(java_object):
    """
    This parses the offset as a big int
    """
    return int(str(java_object.getOffsetAsBigInteger()))


def _register_entry_points(flat_api, entry_points: List[int]):
    """
    Register entry points in the current Ghidra program.

    Marks each address as code and adds it as a labeled external entry point so that
    Ghidra's auto-analysis will discover functions starting at these addresses.
    """
    from ghidra.program.model.symbol import SourceType

    program = flat_api.getCurrentProgram()
    default_space = program.getAddressFactory().getDefaultAddressSpace()
    symbol_table = program.getSymbolTable()

    for i, entry_addr in enumerate(entry_points):
        try:
            addr = default_space.getAddress(entry_addr)
            # Mark as code (matches Java CreateMemoryBlocks.markAsCode)
            code_prop = program.getAddressSetPropertyMap("CodeMap")
            if code_prop is None:
                try:
                    code_prop = program.createAddressSetPropertyMap("CodeMap")
                except Exception:
                    code_prop = program.getAddressSetPropertyMap("CodeMap")
            if code_prop is not None:
                code_prop.add(addr, addr)
            label_name = "entry" if i == 0 else f"entry_{i}"
            symbol_table.createLabel(addr, label_name, SourceType.IMPORTED)
            symbol_table.addExternalEntryPoint(addr)
            LOGGER.info(f"Added entry point at 0x{entry_addr:x}")
        except Exception as e:
            LOGGER.warning(f"Failed to add entry point at 0x{entry_addr:x}: {e}")


def unpack(
    program_file: str,
    decompiled: bool,
    language: Optional[str] = None,
    base_address: Union[str, int, None] = None,
    memory_regions: Optional[List[Dict[str, Any]]] = None,
    entry_points: Optional[List[int]] = None,
    show_progress: bool = False,
):
    try:
        LOGGER.info("Analyzing program. This might take a while.")
        if not program_file and memory_regions and len(memory_regions) > 0:
            # In the case the user passed memory regions and no program_file,
            # we still have to pass a file to pyghidra.open_program, so create a dummy one
            # Data is populated later from the memory regions data.
            tempdir = mkdtemp(prefix="rbs-pyghidra-bin")
            program_file = os.path.join(tempdir, "program")
            with open(program_file, "wb") as f:
                f.write(b"\x00")
        with pyghidra.open_program(program_file, language=language) as flat_api:
            LOGGER.info("Analysis completed. Caching analysis to JSON")
            # Java packages must be imported after pyghidra.start or pyghidra.open_program
            from ghidra.app.decompiler import DecompInterface, DecompileOptions
            from ghidra.util.task import TaskMonitor
            from ghidra.program.model.block import BasicBlockModel
            from ghidra.program.model.symbol import RefType
            from java.math import BigInteger
            from java.io import ByteArrayInputStream

            # If memory_regions are provided, delete all data and create new regions:
            if memory_regions:
                program = flat_api.getCurrentProgram()
                memory = program.getMemory()
                address_factory = program.getAddressFactory()
                default_space = address_factory.getDefaultAddressSpace()

                for block in memory.getBlocks():
                    memory.removeBlock(block, TaskMonitor.DUMMY)

                for region in memory_regions:
                    addr = default_space.getAddress(region["virtual_address"])
                    data_bytes = region["data"]
                    block_name = f"region_{region['virtual_address']:x}"

                    try:
                        # Convert Python bytes to Java InputStream
                        input_stream = ByteArrayInputStream(data_bytes)

                        memory.createInitializedBlock(
                            block_name,
                            addr,
                            input_stream,
                            len(data_bytes),
                            TaskMonitor.DUMMY,
                            False,  # overlay
                        )

                        # Set permissions from region dict.
                        # For backwards compatibility, default to R+X when no permissions are
                        # specified, since previously all MemoryRegions passed to the disassembler
                        # were treated as executable code regions.
                        block = memory.getBlock(addr)
                        permissions = region.get("permissions")
                        if permissions is not None:
                            # permissions is a MemoryPermissions value (int)
                            block.setRead(bool(permissions & MemoryPermissions.R.value))
                            block.setWrite(bool(permissions & MemoryPermissions.W.value))
                            block.setExecute(bool(permissions & MemoryPermissions.X.value))
                        else:
                            # Backwards compatibility: use "executable" flag if present,
                            # otherwise default to executable (R+X) to match legacy behavior
                            is_executable = region.get("executable", True)
                            block.setExecute(is_executable)
                            block.setRead(True)
                    except Exception as e:
                        LOGGER.warning(
                            f"Failed to create memory block at 0x{region['virtual_address']:x}: {e}"
                        )
                if entry_points:
                    _register_entry_points(flat_api, entry_points)

                # Analyze all
                flat_api.analyzeAll(program)
            # If base_address is provided and memory_regions were NOT explicitly provided,
            # rebase the program. When memory_regions are provided, addresses are already
            # absolute and should not be shifted.
            if base_address is not None and not memory_regions:
                # Convert base_address to int if it's a string
                if isinstance(base_address, str):
                    if base_address.startswith("0x"):
                        base_address = int(base_address, 16)
                    else:
                        base_address = int(base_address)

                # Rebase the program to the specified base address
                program = flat_api.getCurrentProgram()
                address_factory = program.getAddressFactory()
                new_base_addr = address_factory.getDefaultAddressSpace().getAddress(
                    hex(base_address)
                )
                program.setImageBase(new_base_addr, True)
                LOGGER.info(f"Rebased program address to {hex(base_address)}")

            # Register entry points for the non-memory_regions path (e.g. raw binary
            # loaded with base_address). For the memory_regions path, entry points are
            # already registered above before analyzeAll.
            if entry_points and not memory_regions:
                _register_entry_points(flat_api, entry_points)
                flat_api.analyzeAll(flat_api.getCurrentProgram())

            main_dictionary: Dict[str, Any] = {}
            code_regions = _unpack_program(flat_api)
            main_dictionary["metadata"] = {}
            main_dictionary["metadata"]["backend"] = "ghidra"
            main_dictionary["metadata"]["decompiled"] = decompiled
            main_dictionary["metadata"]["path"] = program_file
            if base_address is not None:
                main_dictionary["metadata"]["base_address"] = base_address
            with open(program_file, "rb") as fh:
                data = fh.read()
                md5_hash = hashlib.md5(data)
                main_dictionary["metadata"]["hash"] = md5_hash.digest().hex()

            LOGGER.info(f"Program contains {len(code_regions)} code regions")
            for code_region in code_regions:
                seg_key = f"seg_{code_region['virtual_address']}"
                main_dictionary[seg_key] = code_region
                func_cbs = _unpack_code_region(code_region, flat_api)
                code_region["children"] = []

                decomp_interface = DecompInterface()
                prog_options = DecompileOptions()
                prog_options.grabFromProgram(flat_api.getCurrentProgram())
                decomp_interface.setOptions(prog_options)
                init = decomp_interface.openProgram(flat_api.getCurrentProgram())
                if not init:
                    raise RuntimeError("Could not open program for decompilation")

                LOGGER.info(f"Code region {seg_key} contains {len(func_cbs)} complex blocks")
                if len(func_cbs) == 0:
                    continue

                for func, cb in tqdm(func_cbs, unit="CB", smoothing=0, disable=not show_progress):
                    cb_key = f"func_{cb['virtual_address']}"
                    code_region["children"].append(cb_key)
                    if decompiled:
                        try:
                            decompilation = _decompile(func, decomp_interface, TaskMonitor.DUMMY)
                        except Exception as e:
                            print(e, traceback.format_exc())
                            decompilation = ""
                        cb["decompilation"] = decompilation
                    bb_model = BasicBlockModel(flat_api.getCurrentProgram())
                    basic_blocks, data_words = _unpack_complex_block(
                        func, flat_api, bb_model, BigInteger.ONE
                    )
                    cb["children"] = []
                    for block, bb in basic_blocks:
                        if bb["size"] == 0:
                            raise Exception(f"Basic block 0x{bb['virtual_address']:x} has no size")

                        if (
                            bb["virtual_address"] < cb["virtual_address"]
                            or (bb["virtual_address"] + bb["size"])
                            > cb["virtual_address"] + cb["size"]
                        ):
                            LOGGER.warning(
                                f"Basic Block 0x{bb['virtual_address']:x} does not fall within "
                                f"complex block {hex(cb['virtual_address'])}-{hex(cb['virtual_address'] + cb['size'])}"
                            )
                            continue
                        bb_key = f"bb_{bb['virtual_address']}"
                        instructions = _unpack_basic_block(block, flat_api, RefType, BigInteger.ONE)
                        bb["children"] = []
                        for instruction in instructions:
                            instr_key = f"instr_{instruction['virtual_address']}"
                            bb["children"].append(instr_key)
                            main_dictionary[instr_key] = instruction
                        cb["children"].append(bb_key)
                        main_dictionary[bb_key] = bb
                    for dw in data_words:
                        if (
                            dw["virtual_address"] < cb["virtual_address"]
                            or (dw["virtual_address"] + dw["size"])
                            > cb["virtual_address"] + cb["size"]
                        ):
                            LOGGER.warning(
                                f"Data Word 0x{dw['virtual_address']:x} does not fall within "
                                f"complex block {hex(cb['virtual_address'])}-{hex(cb['virtual_address'] + cb['size'])}"
                            )
                            continue
                        dw_key = f"dw_{dw['virtual_address']}"
                        cb["children"].append(dw_key)
                        main_dictionary[dw_key] = dw
                    main_dictionary[cb_key] = cb
    # Loading the file into Ghidra can result in a LoadException. This may occur if Ghidra cannot
    # detect the language. Ideally we would `except LoadException` directly, but it is from Java
    # and can't be imported outside of the `with pyghidra.open_program()` block
    except Exception as e:
        if "toString" in dir(e) and "No load spec found" in e.toString():
            raise PyGhidraComponentException(
                str(type(e))
                + " "
                + e.toString()
                + "\nTry adding ProgramAttributes to you binary before running a Ghidra analyzer/unpacker!"
            )
        else:
            raise PyGhidraComponentException(e)
    return main_dictionary


def _unpack_program(flat_api):
    ghidra_code_regions = []
    for memory_block in flat_api.getMemoryBlocks():
        is_execute = False
        if memory_block.isExecute():
            is_execute = True
        vaddr = _parse_offset(memory_block.getStart())
        size = memory_block.getSize()
        ghidra_code_regions.append(
            {"virtual_address": vaddr, "size": size, "executable": is_execute}
        )
    return _concat_contiguous_code_blocks(ghidra_code_regions)


def _concat_contiguous_code_blocks(code_regions):
    #  Ghidra splits the code into 0x10000 when it is a single segment, so we need to concat contiguous chunks
    code_regions = sorted(code_regions, key=lambda item: item["virtual_address"])
    for i in range(len(code_regions) - 1):
        if (
            code_regions[i]["virtual_address"] + code_regions[i]["size"]
            == code_regions[i + 1]["virtual_address"]
            and code_regions[i]["executable"]
            and code_regions[i + 1]["executable"]
            and code_regions[i]["size"] == 0x10000
        ):
            vaddr = code_regions[i]["virtual_address"]
            size = code_regions[i]["size"] + code_regions[i + 1]["size"]
            code_regions[i] = {"virtual_address": vaddr, "size": size, "executable": True}
            del code_regions[i + 1]
            return _concat_contiguous_code_blocks(code_regions)
    return code_regions


def _unpack_code_region(code_region, flat_api):
    functions = []
    start_address = (
        flat_api.getAddressFactory()
        .getDefaultAddressSpace()
        .getAddress(hex(code_region["virtual_address"]))
    )
    end_address = (
        flat_api.getAddressFactory()
        .getDefaultAddressSpace()
        .getAddress(hex(code_region["virtual_address"] + code_region["size"]))
    )
    func = flat_api.getFunctionAt(start_address)
    if func is None:
        func = flat_api.getFunctionAfter(start_address)
        if func is None:
            return functions

    while func is not None and end_address.compareTo(func.getEntryPoint()) > 0:
        virtual_address = _parse_offset(func.getEntryPoint())
        start = _parse_offset(func.getEntryPoint())
        end, _ = _get_last_address(func, flat_api)
        if end is not None:
            cb = {
                "virtual_address": virtual_address,
                "size": end - start,
                "name": func.getName(),
            }
            functions.append((func, cb))
        func = flat_api.getFunctionAfter(func)
    return functions


def _unpack_complex_block(func, flat_api, bb_model, one):
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
        instruction_mode = "none"
        tmode_register = flat_api.getCurrentProgram().getRegister("TMode")
        if tmode_register is not None:
            function_mode = (
                flat_api.getCurrentProgram()
                .getProgramContext()
                .getRegisterValue(tmode_register, address_range.getMinAddress())
            )
            if function_mode.getUnsignedValueIgnoreMask().equals(one):
                instruction_mode = "thumb"
        vle_register = flat_api.getCurrentProgram().getRegister("vle")
        if vle_register is not None:
            function_mode = (
                flat_api.getCurrentProgram()
                .getProgramContext()
                .getRegisterValue(vle_register, address_range.getMinAddress())
            )
            if function_mode.getUnsignedValueIgnoreMask().equals(one):
                instruction_mode = "vle"
        if is_exit_point:
            exit_vaddr = None

        bb = {
            "virtual_address": start,
            "size": size,
            "mode": instruction_mode,
            "is_exit_point": is_exit_point,
            "exit_vaddr": exit_vaddr,
        }
        bbs.append((ghidra_block, bb))

    end_data_addr, end_code_addr = _get_last_address(func, flat_api)

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

        refs = [
            _parse_offset(ref.getFromAddress())
            for ref in flat_api.getReferencesTo(data.getAddress())
        ]
        for word in range(num_words):
            dws.append(
                {
                    "virtual_address": _parse_offset(data.getAddress()) + word,
                    "size": data.getLength(),
                    "format_string": size_flag,
                    "xrefs_to": tuple(refs),
                }
            )
        data = flat_api.getDataAfter(data)

    return bbs, dws


def _unpack_basic_block(block, flat_api, ref_type, one):
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
        instruction_mode = "none"
        if thumb_register is not None:
            thumb_val = instr.getValue(thumb_register, False)
            if thumb_val.equals(one):
                instruction_mode = "thumb"
        else:
            vle_register = instr.getRegister("vle")
            if vle_register is not None:
                vle_val = instr.getValue(vle_register, False)
                if vle_val.equals(one):
                    instruction_mode = "vle"
        for i in range(int(instr.getNumOperands())):
            ops.append(instr.getDefaultOperandRepresentation(i))
            if i != instr.getNumOperands() - 1:
                ops.append(", ")
            if instr.getOperandRefType(i) == ref_type.READ:
                if instr.getOpObjects(i).length > 0:
                    regs_read.append(
                        instr.getOpObjects(i)[instr.getOpObjects(i).length - 1].toString()
                    )
                if i != instr.getNumOperands() - 1:
                    regs_read.append(", ")

            if instr.getOperandRefType(i) == ref_type.WRITE:
                if instr.getOpObjects(i).length > 0:
                    regs_written.append(
                        instr.getOpObjects(i)[instr.getOpObjects(i).length - 1].toString()
                    )
                if i != instr.getNumOperands() - 1:
                    regs_written.append(", ")

            if instr.getOperandRefType(i) == ref_type.READ_WRITE:
                if instr.getOpObjects(i).length > 0:
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
        operands = re.sub(r" \+ -", " - ", operands)
        operands = re.sub(r",([^\s])", lambda match: f", {match.group(1)}", operands)
        disasm = f"{mnem} {operands}"
        instructions.append(
            {
                "virtual_address": vaddr,
                "size": size,
                "disassembly": disasm,
                "mnemonic": mnem,
                "operands": operands,
                "mode": instruction_mode,
            }
        )
        instr = flat_api.getInstructionAfter(instr_offset)
    return instructions


def _decompile(func, decomp_interface, task_monitor):
    res = decomp_interface.decompileFunction(func, 0, task_monitor)
    if not res.decompileCompleted():
        if res.failedToStart():
            raise RuntimeError(f"Decompiler failed to start")
        raise RuntimeError(f"Unable to decompile {func.getName()}")
    decomp = res.getDecompiledFunction().getC()
    return decomp


def decompile_all_functions(program_file, language):
    with pyghidra.open_program(program_file, language=language) as flat_api:
        from ghidra.app.decompiler import DecompInterface, DecompileOptions
        from ghidra.util.task import TaskMonitor

        decomp = DecompInterface()
        program = flat_api.getCurrentProgram()
        prog_options = DecompileOptions()
        prog_options.grabFromProgram(program)
        decomp.setOptions(prog_options)
        decomp.openProgram(program)
        function_manager = program.getFunctionManager()
        func_to_decomp = {}
        for func in function_manager.getFunctions(True):
            cb_key = f"func_{func.getEntryPoint().getOffset()}"
            decomp_results = decomp.decompileFunction(func, 0, TaskMonitor.DUMMY)
            func_to_decomp[cb_key] = decomp_results.getDecompiledFunction().getC()
        return func_to_decomp


def _get_last_address(func, flat_api):
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


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument(
        "--infile", "-i", type=str, required=True, help="The binary to be analyzed."
    )
    parser.add_argument("--outfile", "-o", type=str, required=True, help="The output json file.")
    parser.add_argument(
        "--decompile", "-d", type=bool, default=False, help="decompile functions in cache"
    )
    parser.add_argument("--language", "-l", default=None, help="Ghidra language id")
    parser.add_argument(
        "--base_address", "-b", default=None, help="Base address to rebase the program to"
    )
    args = parser.parse_args()
    start = time.time()
    logging.basicConfig(
        level=logging.INFO, format="[%(asctime)s|%(name)s|%(levelname)s]: %(message)s"
    )
    LOGGER.info(f"Beginning pyghidra cached analysis for file {args.infile}")
    res = unpack(args.infile, args.decompile, args.language, args.base_address, show_progress=True)
    with open(args.outfile, "w") as fh:
        json.dump(res, fh, indent=4)
    LOGGER.info(f"Wrote cached analysis to {args.outfile}")
    LOGGER.info(f"PyGhidra analysis took {time.time() - start} seconds")
