import logging

import hashlib
import pyghidra
import argparse
import time
import re
import json


def _parse_offset(java_object):
    """
    This parses the offset as a big int
    """
    return int(str(java_object.getOffsetAsBigInteger()))


def unpack(program_file, decompiled, language=None):
    with pyghidra.open_program(program_file, language=language) as flat_api:
        main_dictionary = {}
        code_regions = _unpack_program(flat_api)
        main_dictionary["metadata"] = {}
        main_dictionary["metadata"]["backend"] = "ghidra"
        main_dictionary["metadata"]["decompiled"] = decompiled
        with open(program_file, "rb") as fh:
            data = fh.read()
            md5_hash = hashlib.md5(data)
            main_dictionary["metadata"]["hash"] = md5_hash.digest().hex()
        for code_region in code_regions:
            seg_key = f"seg_{code_region['virtual_address']}"
            main_dictionary[seg_key] = code_region
            func_cbs = _unpack_code_region(code_region, flat_api)
            code_region["children"] = []
            for func, cb in func_cbs:
                cb_key = f"func_{cb['virtual_address']}"
                code_region["children"].append(cb_key)
                if decompiled:
                    decompilation = _decompile(func, flat_api)
                    cb["decompilation"] = decompilation
                basic_blocks, data_words = _unpack_complex_block(func, flat_api)
                cb["children"] = []
                for block, bb in basic_blocks:
                    if bb["size"] == 0:
                        raise Exception(f"Basic block 0x{bb['virtual_address']:x} has no size")

                    if (
                        bb["virtual_address"] < cb["virtual_address"]
                        or (bb["virtual_address"] + bb["size"]) > cb["virtual_address"] + cb["size"]
                    ):
                        logging.warning(
                            f"Basic Block 0x{bb['virtual_address']:x} does not fall within "
                            f"complex block {hex(cb['virtual_address'])}-{hex(cb['virtual_address'] + cb['size'])}"
                        )
                        continue
                    bb_key = f"bb_{bb['virtual_address']}"
                    instructions = _unpack_basic_block(block, flat_api)
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
                        or (dw["virtual_address"] + dw["size"]) > cb["virtual_address"] + cb["size"]
                    ):
                        logging.warning(
                            f"Data Word 0x{dw['virtual_address']:x} does not fall within "
                            f"complex block {hex(cb['virtual_address'])}-{hex(cb['virtual_address'] + cb['size'])}"
                        )
                        continue
                    dw_key = f"dw_{dw['virtual_address']}"
                    cb["children"].append(dw_key)
                    main_dictionary[dw_key] = dw
                main_dictionary[cb_key] = cb
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
    for i in range(len(code_regions) - 1):
        if (
            code_regions[i]["virtual_address"] + code_regions[i]["size"]
            == code_regions[i + 1]["virtual_address"]
            and code_regions[i]["executable"]
            and code_regions[i + 1]["executable"]
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

    while func is not None and end_address.subtract(func.getEntryPoint()) > 0:
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


def _unpack_complex_block(func, flat_api):
    from ghidra.program.model.block import BasicBlockModel

    bb_model = BasicBlockModel(flat_api.getCurrentProgram())
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

        instruction_mode = "none"
        tmode_register = flat_api.getCurrentProgram().getRegister("TMode")
        if tmode_register is not None:
            function_mode = (
                flat_api.getCurrentProgram()
                .getProgramContext()
                .getRegisterValue(tmode_register, address_range.getMinAddress())
            )
            if function_mode.getUnsignedValueIgnoreMask().equals(BigInteger.ONE):
                instruction_mode = "thumb"
        vle_register = flat_api.getCurrentProgram().getRegister("vle")
        if vle_register is not None:
            function_mode = (
                flat_api.getCurrentProgram()
                .getProgramContext()
                .getRegisterValue(vle_register, address_range.getMinAddress())
            )
            if function_mode.getUnsignedValueIgnoreMask().equals(BigInteger.ONE):
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


def _unpack_basic_block(block, flat_api):
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
        instruction_mode = "none"
        if thumb_register is not None:
            thumb_val = instr.getValue(thumb_register, False)
            if thumb_val.equals(BigInteger.ONE):
                instruction_mode = "thumb"
        else:
            vle_register = instr.getRegister("vle")
            if vle_register is not None:
                vle_val = instr.getValue(vle_register, False)
                if vle_val.equals(BigInteger.ONE):
                    instruction_mode = "vle"
        for i in range(int(instr.getNumOperands())):
            ops.append(instr.getDefaultOperandRepresentation(i))
            if i != instr.getNumOperands() - 1:
                ops.append(", ")
            if instr.getOperandRefType(i) == RefType.READ:
                regs_read.append(instr.getOpObjects(i)[instr.getOpObjects(i).length - 1].toString())
                if i != instr.getNumOperands() - 1:
                    regs_read.append(", ")

            if instr.getOperandRefType(i) == RefType.WRITE:
                regs_written.append(
                    instr.getOpObjects(i)[instr.getOpObjects(i).length - 1].toString()
                )
                if i != instr.getNumOperands() - 1:
                    regs_written.append(", ")

            if instr.getOperandRefType(i) == RefType.READ_WRITE:
                regs_read.append(instr.getOpObjects(i)[instr.getOpObjects(i).length - 1].toString())
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


def _decompile(func, flat_api):
    from ghidra.app.decompiler import DecompInterface
    from ghidra.util.task import TaskMonitor

    ifc = DecompInterface()
    ifc.openProgram(flat_api.getCurrentProgram())
    res = ifc.decompileFunction(func, 0, TaskMonitor.DUMMY)
    if not res.decompileCompleted():
        decomp = "Unable to decompile :("
        return
    decomp = res.getDecompiledFunction().getC()
    return decomp


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
    args = parser.parse_args()
    start = time.time()
    res = unpack(args.infile, args.decompile, args.language)
    with open(args.outfile, "w") as fh:
        json.dump(res, fh, indent=4)
    print(f"PyGhidra analysis took {time.time() - start} seconds")
