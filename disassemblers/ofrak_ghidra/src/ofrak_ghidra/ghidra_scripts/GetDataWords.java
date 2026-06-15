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

public class GetDataWords extends HeadlessScript {
    @Override
    public void run() throws Exception {
        try {
            String[] startAddresses = getScriptArgs()[0].split(",");
            String[] endAddresses = getScriptArgs()[1].split(",");
            StringBuilder resultStringBuilder = new StringBuilder("[");

            Address startAddr;
            Address endAddr;
            String response;

            for (int i = 0; i < startAddresses.length; i++){
                startAddr = toAddr(startAddresses[i]);
                endAddr = toAddr(endAddresses[i]);
                response = new GetDataWords.Result(startAddr, endAddr).toJson();
                resultStringBuilder.append(response);
                resultStringBuilder.append(",");
            }
            resultStringBuilder.deleteCharAt(resultStringBuilder.length() - 1); // remove last comma
            resultStringBuilder.append("]");
            String finalResponse = resultStringBuilder.toString();

            storeHeadlessValue("OfrakResult_GetDataWords", finalResponse);
        } catch(Exception e) {
            println(e.toString());
            throw e;
        }
    }


    class Result {
        final List<GetDataWords.ResultDataWord> dataWords;

        Result(Address startAddr, Address endAddr) throws CancelledException {
            Data data = getDataAt(startAddr);

            if (data == null) {
                data = getDataAfter(startAddr);
            }
            this.dataWords = new ArrayList<>();
            while (data != null && data.getAddress().getOffset() <= endAddr.getOffset()) {
                this.dataWords.add(new GetDataWords.ResultDataWord(data));
                data = getDataAfter(data);
            }
        }

        String toJson() {
            String dwString = dataWords.stream()
                    .map(GetDataWords.ResultDataWord::toJson)
                    .collect(Collectors.joining(", "));
            return String.format("[%s]", dwString);
        }
    }


    class ResultDataWord {
        final long word_vaddr;
        final long word_size;
        final List<Long> xrefs = new ArrayList<Long>();

        ResultDataWord(Data data) {
            this.word_vaddr = data.getAddress().getOffset();
            this.word_size = data.getLength();
            Reference[] references = getReferencesTo(data.getAddress());
            for (Reference ref: references) {
                this.xrefs.add(ref.getFromAddress().getOffset());
            }
        }

        String toJson() {
            return String.format(
                "{\"word_vaddr\":%s,\"word_size\":%s,\"xrefs\":%s}", 
                Long.toUnsignedString(word_vaddr), 
                Long.toUnsignedString(word_size), 
                xrefs.toString()
            );
        }
    }
}
