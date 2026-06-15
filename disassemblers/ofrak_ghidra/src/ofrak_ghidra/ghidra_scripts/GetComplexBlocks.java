import com.google.common.base.Strings;
import ghidra.app.util.headless.HeadlessScript;
import ghidra.app.script.GhidraState;
import ghidra.program.model.address.Address;
import ghidra.program.model.address.AddressRange;
import ghidra.program.model.address.AddressRangeIterator;
import ghidra.program.model.address.AddressSet;
import ghidra.program.model.block.BasicBlockModel;
import ghidra.program.model.block.CodeBlock;
import ghidra.program.model.block.CodeBlockIterator;
import ghidra.program.model.block.CodeBlockModel;
import ghidra.program.model.listing.*;
import ghidra.program.model.mem.Memory;
import ghidra.program.model.mem.MemoryBlock;
import ghidra.program.model.mem.MemoryBlockSourceInfo;
import ghidra.program.model.pcode.PcodeOp;
import ghidra.util.exception.CancelledException;
import ghidra.util.task.TaskMonitor;
import ghidra.program.model.lang.Register;
import ghidra.program.model.lang.RegisterValue;
import ghidra.program.model.symbol.Reference;
import ghidra.program.model.block.CodeBlockReferenceIterator;
import ghidra.program.model.symbol.ReferenceIterator;
import ghidra.program.model.symbol.RefType;

import java.io.IOException;
import java.util.*;
import java.util.function.Predicate;
import java.util.stream.Collectors;
import java.math.BigInteger;

public class GetComplexBlocks extends HeadlessScript {
    @Override
    public void run() throws Exception {
        try{
            Address startAddr = toAddr(getScriptArgs()[0]);
            Address endAddr = toAddr(getScriptArgs()[1]);

            String response = new GetComplexBlocks.Result(startAddr, endAddr).toJson();
            storeHeadlessValue("OfrakResult_GetComplexBlocks", response);
        } catch (Exception e){
            println(e.toString());
            throw e;
        }
    }


    class Result {
        final List<GetComplexBlocks.ResultComplexBlock> complexBlocks;

        Result(Address start, Address end) throws CancelledException {
            AddressSet blockAddressSet = currentProgram.getAddressFactory().getAddressSet(start, end);
            this.complexBlocks = new ArrayList<>();

            // Get the first function at or after "start".
            Function func = getFunctionAt(start);

            if (func == null) {
                func = getFunctionAfter(start);

                if (func == null) {
                    return;
                }
            }

            while (func != null && end.subtract(func.getEntryPoint()) > 0) {
                GetComplexBlocks.ResultComplexBlock rezzy = new GetComplexBlocks.ResultComplexBlock(start, end, func);
                func = getFunctionAfter(func);

                if (rezzy.size > 0) {
                    complexBlocks.add(rezzy);
                }
            }
        }

        String toJson() {
            String cbString = complexBlocks.stream()
                    .map(GetComplexBlocks.ResultComplexBlock::toJson)
                    .collect(Collectors.joining(", "));
            return String.format("[%s]", cbString);
        }
    }


    class ResultComplexBlock {
        final long loadAddress;
        final long sectionOffset;
        final long size;
        final String name;

        ResultComplexBlock(Address start, Address end, Function function) throws CancelledException {
            Address functionEntryAddress = function.getEntryPoint();
            this.loadAddress = functionEntryAddress.getOffset();
            this.sectionOffset = functionEntryAddress.subtract(start);
            this.name = function.getName();

            Function nextFunc = getFunctionAfter(function);
            Address nextFuncAddr = null;
            if (nextFunc == null) {
                nextFuncAddr = function.getBody().getMaxAddress();
            }
            else {
                nextFuncAddr = nextFunc.getEntryPoint();
            }
            AddressRangeIterator addressIterator = function.getBody().getAddressRanges();

            // Figure out the endAddr, ensuring that it is not greater than nextFuncAddr
            Address endAddr = null;
            while (addressIterator.hasNext()) {
                AddressRange range = addressIterator.next();
                if (endAddr == null){
                    ;
                }
                else if (range.getMaxAddress().subtract(nextFuncAddr) > 0){
                    break;
                }
                endAddr = range.getMaxAddress();
            }
            Instruction lastInsn = getInstructionAt(endAddr);

            if (lastInsn == null) {
                lastInsn = getInstructionBefore(endAddr);
            }

            if (lastInsn == null) {
                endAddr = endAddr.add(1);
            }
            else if (function.equals(getFunctionContaining(lastInsn.getAddress()))) {
                endAddr = lastInsn.getAddress().add(lastInsn.getLength());
            }

            // Note we can't get the literal pool after the last function in the section.
            if (getFunctionAfter(function) == null) {
                this.size = endAddr.getOffset() - this.loadAddress;
                return;
            }

            if (nextFuncAddr.subtract(end) > 0) {
                this.size = endAddr.getOffset() - this.loadAddress;
                return;
            }

            Data data = getDataAt(endAddr);

            if (data == null) {
                data = getDataAfter(endAddr);
            }

            while (data != null && nextFuncAddr.subtract(data.getAddress()) > 0) {
                endAddr = data.getAddress().add(data.getLength());
                data = getDataAfter(data);
            }
            this.size = endAddr.getOffset() - this.loadAddress;
        }

        String toJson() {
            return String.format(
                "{\"loadAddress\":%s,\"sectionOffset\":%s,\"size\":%s,\"name\":\"%s\"}", 
                Long.toUnsignedString(loadAddress), 
                Long.toUnsignedString(sectionOffset), 
                Long.toUnsignedString(size), 
                name.replace("\"", "\\\"")
            );
        }
    }
}
