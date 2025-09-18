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

public class GetCallGraph extends HeadlessScript {
    @Override
    public void run() throws Exception {
        try {
            Address startAddr = toAddr(getScriptArgs()[0]);
            Address endAddr = toAddr(getScriptArgs()[1]);
            String response = new GetCallGraph.Result(startAddr, endAddr).toJson();

            storeHeadlessValue("OfrakResult_GetCallGraph", response);
        } catch(Exception e) {
            println(e.toString());
            throw e;
        }
    }


    class Result {
        final Map<Long, List<Long>> callGraph;

        Result(Address start, Address end) {
            AddressSet blockAddressSet = currentProgram.getAddressFactory().getAddressSet(start, end);
            this.callGraph = new HashMap<Long, List<Long>>();

            Address funcAddr = start.add(0);
            Function func = getFunctionAt(funcAddr);

            if (func == null) {
                func = getFunctionAfter(funcAddr);

                if (func == null) {
                    return;
                }
            }

            while (func != null && end.subtract(func.getEntryPoint()) > 0) {
                Set<Function> calledFuncs = func.getCalledFunctions(TaskMonitor.DUMMY);
                ArrayList<Long> calledFuncAddrs = new ArrayList<>();

                for (Function calledFunc : calledFuncs) {
                    calledFuncAddrs.add(calledFunc.getEntryPoint().getOffset());
                }

                this.callGraph.put(func.getEntryPoint().getOffset(), calledFuncAddrs);
                func = getFunctionAfter(func);
            }
        }

        String kvToStr(Map.Entry<Long, List<Long>> entry) {
            String addrStr = String.valueOf(entry.getKey());

            String succStr = entry.getValue().stream()
                                .map(off -> String.valueOf(off))
                                .collect(Collectors.joining(", "));

            return String.format("{\"addr\": %s, \"succs\": [%s]}", addrStr, succStr);
        }

        String toJson() {
            String graphRepr = this.callGraph.entrySet().stream()
                                    .map(kv -> kvToStr(kv))
                                    .collect(Collectors.joining(", "));

            return String.format("[%s]", graphRepr);
        }
    }
}
