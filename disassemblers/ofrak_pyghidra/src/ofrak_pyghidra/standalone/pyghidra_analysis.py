import os
import hashlib
import logging
import os
import re
from typing import Any, Dict, Optional, Union, List

from ofrak import Resource


LOGGER = logging.getLogger("ofrak_pyghidra")
_DEFAULT_CACHE_DIR = os.path.join(os.path.expanduser("~"), ".cache", "ofrak-pyghidra")
PYGHIDRA_CACHE_DIR = os.environ.get("OFRAK_PYGHIDRA_CACHE_DIR", _DEFAULT_CACHE_DIR)


class PyGhidraComponentException(Exception):
    pass


def _parse_offset(java_object):
    """
    This parses the offset as a big int
    """
    return int(str(java_object.getOffsetAsBigInteger()))


async def _compute_cache_key(resource, language, memory_regions, base_address):
    """Compute a stable MD5 hash from all inputs that affect Ghidra analysis."""
    h = hashlib.md5()
    h.update(await resource.get_data())
    if language:
        h.update(language.encode())
    if base_address is not None:
        h.update(str(base_address).encode())
    if memory_regions:
        for region in sorted(memory_regions, key=lambda r: r["virtual_address"]):
            h.update(region["virtual_address"].to_bytes(8, "big"))
            h.update(region["data"])
    return h.hexdigest()


async def prepare_project(
    resource: Resource,
    language: Optional[str] = None,
    base_address: Union[str, int, None] = None,
    memory_regions: Optional[List[Dict[str, Any]]] = None,
) -> Dict[str, Any]:
    """Compute cache key and project params without opening anything.

    Returns a dict with keys: program_file, project_location, project_name, cached.
    """
    cache_key = await _compute_cache_key(resource, language, memory_regions, base_address)
    cache_dir = PYGHIDRA_CACHE_DIR
    os.makedirs(cache_dir, exist_ok=True)

    project_name = f"{cache_key}_ghidra"
    project_dir = os.path.join(cache_dir, project_name)
    gpr_file = os.path.join(project_dir, f"{project_name}.gpr")
    cached = os.path.exists(gpr_file)

    cached_program = os.path.join(cache_dir, cache_key)
    with open(cached_program, "wb") as f:
        f.write(await resource.get_data())
    return {
        "cache_key": cache_key,
        "program_file": cached_program,
        "project_location": cache_dir,
        "project_name": project_name,
        "cached": cached,
        "language": language,
    }


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
