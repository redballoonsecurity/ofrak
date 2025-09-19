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


public class GetBasicBlocks extends HeadlessScript {
    @Override
    public void run() throws Exception {
        try {
            String[] startOffsets = getScriptArgs()[0].split(",");
            String[] startAddresses = getScriptArgs()[1].split(",");
            StringBuilder resultStringBuilder = new StringBuilder("[");

            Address startOffset;
            Address startAddr;
            String response;

            for (int i = 0; i < startOffsets.length; i++){
                startOffset = toAddr(startOffsets[i]);
                startAddr = toAddr(startAddresses[i]);
                response = new GetBasicBlocks.Result(startOffset, startAddr).toJson();
                resultStringBuilder.append(response);
                resultStringBuilder.append(",");
            }

            resultStringBuilder.deleteCharAt(resultStringBuilder.length() - 1); // remove last comma
            resultStringBuilder.append("]");
            String finalResponse = resultStringBuilder.toString();

            storeHeadlessValue("OfrakResult_GetBasicBlocks", finalResponse);

        } catch(Exception e) {
            println(e.toString());
            throw e;
        }
    }


    class Result {
        final List<GetBasicBlocks.ResultBasicBlock> basicBlocks;

        Result(Address startOffset, Address startAddr) throws CancelledException {
            CodeBlockModel blockModel = new BasicBlockModel(currentProgram);
            Function function = currentProgram.getFunctionManager().getFunctionAt(startAddr);

            this.basicBlocks = new ArrayList<>();
            CodeBlockIterator iterator = blockModel.getCodeBlocksContaining(function.getBody(), monitor);
            while (iterator.hasNext()) {
                this.basicBlocks.add(new GetBasicBlocks.ResultBasicBlock(function.getEntryPoint(), iterator.next()));
            }
        }

        String toJson() {
            String bbString = basicBlocks.stream()
                    .map(GetBasicBlocks.ResultBasicBlock::toJson)
                    .collect(Collectors.joining(", "));
            return String.format("[%s]", bbString);
        }
    }


    class ResultBasicBlock {
        final long bb_start_vaddr;
        final long bb_size;
        final boolean is_exit_point;
        final long exit_vaddr;
        String instruction_mode;

        ResultBasicBlock(Address functionStart, CodeBlock codeBlock) throws CancelledException {
            if (codeBlock.getNumAddressRanges() > 1) {
                throw new RuntimeException("This is unexpected... figure out why this happens");
            }
            AddressRange addressRange = codeBlock.getAddressRanges().next();

            this.bb_start_vaddr = addressRange.getMinAddress().getOffset();
            this.bb_size = addressRange.getLength();

            Function function = currentProgram.getFunctionManager().getFunctionAt(functionStart);

            boolean is_exit_point = true;
            long exit_vaddr = -1;
            CodeBlockReferenceIterator iterator = codeBlock.getDestinations(monitor);
            while (iterator.hasNext()) {
                CodeBlock successor_bb = iterator.next().getDestinationBlock();
                AddressRange successor_bb_addressRange = successor_bb.getAddressRanges().next();
                // Check if the successor is in the function (in the ComplexBlock), discard the destinations that are not.
                if (successor_bb_addressRange.getMinAddress().getOffset() >= function.getBody().getMinAddress().getOffset() && successor_bb_addressRange.getMaxAddress().getOffset() <= function.getBody().getMaxAddress().getOffset()){
                    is_exit_point = false;
                    if(exit_vaddr == -1 || successor_bb_addressRange.getMinAddress().getOffset() == addressRange.getMaxAddress().getOffset()+1) {
                        exit_vaddr = successor_bb_addressRange.getMinAddress().getOffset();
                    }
                }
            }
            this.exit_vaddr = exit_vaddr;
            this.is_exit_point = is_exit_point;

            // Try to get the Thumb register and check its value
            try {
                Register tmode_register = currentProgram.getRegister("TMode");
                RegisterValue function_mode = currentProgram.getProgramContext().getRegisterValue(tmode_register, addressRange.getMinAddress());
                this.instruction_mode = function_mode.getUnsignedValueIgnoreMask().equals(BigInteger.ONE) ? "THUMB" : "NONE" ;
            } catch(Exception e) {
                this.instruction_mode = "NONE";
            }
            // Try to get the vle register and check its value
            try {
                Register vle_register = currentProgram.getRegister("vle");
                RegisterValue function_mode = currentProgram.getProgramContext().getRegisterValue(vle_register, addressRange.getMinAddress());
                this.instruction_mode = function_mode.getUnsignedValueIgnoreMask().equals(BigInteger.ONE) ? "VLE" : this.instruction_mode;
            } catch(Exception e) {
                // Pass
            }
        }

        String toJson() {
            return String.format(
                "{\"bb_start_vaddr\":%s,\"bb_size\":%s,\"is_exit_point\":%b,\"instr_mode\":\"%s\",\"exit_vaddr\":%s}", 
                Long.toUnsignedString(bb_start_vaddr), 
                Long.toUnsignedString(bb_size), 
                is_exit_point, 
                instruction_mode, 
                Long.toUnsignedString(exit_vaddr)
            );
        }
    }
}
