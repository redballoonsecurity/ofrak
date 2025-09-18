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
import ghidra.app.decompiler.DecompInterface;
import ghidra.app.decompiler.DecompileResults;

import java.io.IOException;
import java.util.*;
import java.util.function.Predicate;
import java.util.stream.Collectors;
import java.math.BigInteger;

public class GetDecompilation extends HeadlessScript {
    @Override
    public void run() throws Exception {
        try {
            Integer funcAddr = Integer.parseInt(getScriptArgs()[0]);
            Function func = getFunctionAt(toAddr(funcAddr));
            String response = new GetDecompilation.Result(func).toJson();

            storeHeadlessValue("OfrakResult_GetDecompilation", response);
        } catch(Exception e) {
            println(e.toString());
            throw e;
        }
    }


    class Result {
        final String decomp;

        Result(Function func) throws CancelledException {
            DecompInterface ifc = new DecompInterface();
            ifc.openProgram(currentProgram);

            DecompileResults res = ifc.decompileFunction(func, 0, TaskMonitor.DUMMY);
            if (!res.decompileCompleted()) {
                decomp = "Unable to decompile :(";
                return;
            }

            decomp = res.getDecompiledFunction().getC();
        }

        String toJson() {
            String escaped_decomp = decomp.replace("\"", "<dquote>")
                                          .replace("'", "<quote>")
                                          .replace("\n", "<nl>")
                                          .replace("\0", "<zero>")
                                          .replace("\t", "<tab>")
                                          .replace("\r", "<cr>")
                                          .replace("\\", "<escape>");
            return String.format("{\"decomp\": \"%s\"}", escaped_decomp);
        }
    }
}
