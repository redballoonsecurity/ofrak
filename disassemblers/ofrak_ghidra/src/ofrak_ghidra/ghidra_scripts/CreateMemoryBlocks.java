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
import ghidra.program.model.util.AddressSetPropertyMap;
import ghidra.program.model.symbol.*;


import java.io.IOException;
import java.io.OutputStream;
import java.util.*;
import java.lang.IllegalArgumentException;
import java.lang.IndexOutOfBoundsException;
import ghidra.util.exception.InvalidInputException;

import static java.util.stream.Collectors.mapping;
import static java.util.stream.Collectors.toList;

public class CreateMemoryBlocks extends HeadlessScript {

    private final static String ENTRY_NAME = "entry";

    @Override
    public void run() throws Exception {
        String[] args = getScriptArgs();

        Memory mem = currentProgram.getMemory();
        FileBytes fileBytes = mem.getAllFileBytes().get(0);
        SymbolTable symbolTable = currentProgram.getSymbolTable();

        // remove existing memory blocks
        for (MemoryBlock block : mem.getBlocks()){
            mem.removeBlock(block, TaskMonitor.DUMMY);
        }

        // Collect explicit entry points from arguments (format: "entry:0x1000,0x2000")
        List<Long> explicitEntryPoints = new ArrayList<>();

        for (String arg : args) {
            if (arg.startsWith("entry:")) {
                String entryList = arg.substring(6);  // Remove "entry:" prefix
                for (String entryStr : entryList.split(",")) {
                    try {
                        long entryAddr;
                        if (entryStr.startsWith("0x") || entryStr.startsWith("0X")) {
                            entryAddr = Long.parseUnsignedLong(entryStr.substring(2), 16);
                        } else {
                            entryAddr = Long.parseUnsignedLong(entryStr);
                        }
                        explicitEntryPoints.add(entryAddr);
                    } catch (NumberFormatException e) {
                        println("Warning: Failed to parse entry point: " + entryStr);
                    }
                }
            }
        }

        boolean hasExplicitEntryPoints = !explicitEntryPoints.isEmpty();

        for (String memRegionRaw : args) {
            // Skip entry point argument
            if (memRegionRaw.startsWith("entry:")) {
                continue;
            }

            String[] memRegionInfo = memRegionRaw.split("!");

            int address = Integer.parseInt(memRegionInfo[0]);
            int size = Integer.parseInt(memRegionInfo[1]);
            String permissions = memRegionInfo[2];
            String name = memRegionInfo[3];
            int offset = Integer.parseInt(memRegionInfo[4]);

            MemoryBlock block;

            try {
                if (offset >= 0){
                    block = mem.createInitializedBlock(name, toAddr(address), fileBytes, offset, size, false);
                } else {
                    block = mem.createUninitializedBlock(name, toAddr(address), size, false);
                }
                block.setPermissions(
                    permissions.contains("r"), permissions.contains("w"), permissions.contains("x")
                );
            } catch (Exception e) {
                    e.printStackTrace();
                    continue;
            }

            // Only add block start as entry point if no explicit entry points provided
            // and the block is executable
            if (!hasExplicitEntryPoints && permissions.contains("x")){

                markAsCode(currentProgram, block.getStart());

                try {
                    symbolTable.createLabel(block.getStart(), ENTRY_NAME, SourceType.IMPORTED);
                    symbolTable.addExternalEntryPoint(block.getStart());
                }
                catch (InvalidInputException e) {
                    e.printStackTrace();
                    continue;
                }

            }

        }

        // Add explicit entry points
        int entryIndex = 0;
        for (Long entryAddr : explicitEntryPoints) {
            Address addr = toAddr(entryAddr);
            markAsCode(currentProgram, addr);

            try {
                String labelName = entryIndex == 0 ? ENTRY_NAME : ENTRY_NAME + "_" + entryIndex;
                symbolTable.createLabel(addr, labelName, SourceType.IMPORTED);
                symbolTable.addExternalEntryPoint(addr);
                entryIndex++;
            }
            catch (InvalidInputException e) {
                e.printStackTrace();
            }
        }
    }

    private void markAsCode(Program program, Address address) {
		AddressSetPropertyMap codeProp = program.getAddressSetPropertyMap("CodeMap");
		if (codeProp == null) {
			try {
				codeProp = program.createAddressSetPropertyMap("CodeMap");
			}
			catch (DuplicateNameException e) {
				codeProp = program.getAddressSetPropertyMap("CodeMap");
			}
		}

		if (codeProp != null) {
			codeProp.add(address, address);
		}
	}

}
