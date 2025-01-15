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

public class GetCodeRegionsDuplicate extends HeadlessScript {
    @Override
    public void run() throws Exception {
        try{
            String response = new GetCodeRegionsDuplicate.Result().toJson();
            storeHeadlessValue("OfrakResult_GetCodeRegions", response);
        } catch (Exception e){
            println(e.toString());
            throw e;
        }
    }


    class Result {
        final List<GetCodeRegionsDuplicate.ResultCodeRegion> codeRegions;

        Result() throws CancelledException {
            this.codeRegions = new ArrayList<>();

            MemoryBlock[] blocks = getMemoryBlocks();
            int i;

            for (i=0; i<blocks.length; i++) {
                MemoryBlock block = blocks[i];

                if (block.isExecute()) {
                    GetCodeRegionsDuplicate.ResultCodeRegion cr = new GetCodeRegionsDuplicate.ResultCodeRegion(block);
                    codeRegions.add(cr);
                }
            }
        }

        String toJson() {
            String cbString = codeRegions.stream()
                    .map(GetCodeRegionsDuplicate.ResultCodeRegion::toJson)
                    .collect(Collectors.joining(", "));
            return String.format("[%s]", cbString);
        }
    }


    class ResultCodeRegion {
        final long start;
        final long size;
        final String name;

        ResultCodeRegion(MemoryBlock block) throws CancelledException {
            this.start = block.getStart().getOffset();
            this.size = block.getSize();
            this.name = block.getName();
        }

        String toJson() {
            return String.format("{\"start\":%d,\"size\":%d,\"name\":\"%s\"}", start, size, name.replace("\"", "\\\""));
        }
    }
}
