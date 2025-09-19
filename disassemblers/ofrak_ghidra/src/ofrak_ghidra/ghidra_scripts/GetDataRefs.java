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

public class GetDataRefs extends HeadlessScript {
    @Override
    public void run() throws Exception {
        try {
            String response = new GetDataRefs.Result().toJson();

            storeHeadlessValue("OfrakResult_GetDataRefs", response);
        } catch(Exception e) {
            println(e.toString());
            throw e;
        }
    }


    class Result {
        final List<GetDataRefs.ResultDataRef> dataRefs;

        Result() throws CancelledException {
            ReferenceIterator iterator = currentProgram.getReferenceManager().getReferenceIterator(toAddr(0));
            this.dataRefs = new ArrayList<>();
            // TODO: this is not pretty, we should find another way to check if data_ref was already added to the list
            final List<Long> alreadyAdded = new ArrayList<Long>();
            while (iterator.hasNext()) {
                Reference ref = iterator.next();
                if (ref.getReferenceType().isData()){
                    ResultDataRef data_ref = new GetDataRefs.ResultDataRef(ref);
                    if (!alreadyAdded.contains(data_ref.data_address) && !data_ref.xrefs.isEmpty()){
                        this.dataRefs.add(data_ref);
                        alreadyAdded.add(data_ref.data_address);
                    }
                }
            }
        }

        String toJson() {
            String dataRefsString = dataRefs.stream()
                    .map(GetDataRefs.ResultDataRef::toJson)
                    .collect(Collectors.joining(", "));
            return String.format("[%s]", dataRefsString);
        }
    }


    class ResultDataRef {
        final long data_address;
        final List<Long> xrefs = new ArrayList<Long>();

        ResultDataRef(Reference ref) {
            this.data_address = ref.getToAddress().getOffset();
            try {
                // We have to try/catch this because: getReferencesTo not supported for stack/register addresses
                ReferenceIterator iterator = currentProgram.getReferenceManager().getReferencesTo(ref.getToAddress());
                while (iterator.hasNext()) {
                    this.xrefs.add(iterator.next().getFromAddress().getOffset());
                }
            } catch(UnsupportedOperationException e) {
                // don't care about the stack/register addresses
            } catch(Exception e) {
                e.printStackTrace();
            }
        }

        String toJson() {
            return String.format(
                "{\"data_address\":%s,\"xrefs\":%s}", 
                Long.toUnsignedString(data_address), 
                xrefs.toString()
            );
        }
    }
}
