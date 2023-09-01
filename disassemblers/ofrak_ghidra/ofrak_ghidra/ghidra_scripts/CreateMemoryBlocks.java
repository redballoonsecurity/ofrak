import com.google.common.base.Strings;
import com.google.common.base.Strings;
import com.sun.net.httpserver.HttpExchange;
import com.sun.net.httpserver.HttpHandler;
import com.sun.net.httpserver.HttpServer;
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
import java.math.BigInteger;
import ghidra.program.model.symbol.Reference;
import ghidra.program.model.block.CodeBlockReferenceIterator;
import ghidra.program.model.symbol.ReferenceIterator;
import ghidra.program.model.symbol.RefType;
import ghidra.framework.store.LockException;
import ghidra.util.exception.DuplicateNameException;
import ghidra.program.model.mem.MemoryConflictException;
import ghidra.program.model.address.AddressOverflowException;
import ghidra.program.database.mem.FileBytes;


import java.io.IOException;
import java.io.OutputStream;
import java.util.*;
import java.lang.IllegalArgumentException;
import java.lang.IndexOutOfBoundsException;

import static java.util.stream.Collectors.mapping;
import static java.util.stream.Collectors.toList;

public class CreateMemoryBlocks extends HeadlessScript {

    @Override
    public void run() throws Exception {
        String[] args = getScriptArgs();

        Memory mem = currentProgram.getMemory();
        FileBytes fileBytes = mem.getAllFileBytes().get(0);

        for (String memRegionRaw : args) {

            String[] memRegionInfo = memRegionRaw.split("!");

            int address = Integer.parseInt(memRegionInfo[0]);
            int size = Integer.parseInt(memRegionInfo[1]);
            String permissions = memRegionInfo[2];
            String name = memRegionInfo[3];
            int offset = Integer.parseInt(memRegionInfo[4]);

            MemoryBlock block;

            try {
                if (offset >= 0){
                    block = mem.createInitializedBlock(name, toAddr(address), fileBytes, offset, size, true);
                } else {
                    block = mem.createUninitializedBlock(name, toAddr(address), size, false);
                }
                block.setPermissions(
                    permissions.contains("r"), permissions.contains("w"), permissions.contains("x")
                );
            } catch (LockException e) {
                    e.printStackTrace();
            } catch (IllegalArgumentException e) {
                    e.printStackTrace();
            } catch (IndexOutOfBoundsException e) {
                    e.printStackTrace();
            } catch (MemoryConflictException e) {
                    e.printStackTrace();
            } catch (AddressOverflowException e) {
                    e.printStackTrace();
            }


        }
    }


}
