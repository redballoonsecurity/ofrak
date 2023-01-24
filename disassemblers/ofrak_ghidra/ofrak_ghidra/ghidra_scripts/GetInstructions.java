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

import java.util.*;
import static java.util.stream.Collectors.mapping;
import static java.util.stream.Collectors.toList;
import java.util.stream.Collectors;
import java.math.BigInteger;
import ghidra.program.model.listing.*;

public class GetInstructions extends HeadlessScript {
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
                response = new GetInstructions.Result(startAddr, endAddr).toJson();
                resultStringBuilder.append(response);
                resultStringBuilder.append(",");
            }
            resultStringBuilder.deleteCharAt(resultStringBuilder.length() - 1); // remove last comma
            resultStringBuilder.append("]");
            String finalResponse = resultStringBuilder.toString();

            storeHeadlessValue("OfrakResult_GetInstructions", finalResponse);
        } catch(Exception e) {
            println(e.toString());
            throw e;
        }
    }

    class Result {
        final List<GetInstructions.ResultInstruction> instructions;

        Result(Address startAddr, Address endAddr) throws CancelledException {
            Instruction instruction = getInstructionAt(startAddr);

            if (instruction == null) {
                instruction = getInstructionAfter(startAddr);
            }

            this.instructions = new ArrayList<>();

            while (instruction != null && instruction.getAddress().getOffset() <= endAddr.getOffset()) {
                this.instructions.add(new GetInstructions.ResultInstruction(instruction));
                instruction = getInstructionAfter(instruction);
            }
        }

        String toJson() {
            String instrString = instructions.stream()
                    .map(GetInstructions.ResultInstruction::toJson)
                    .collect(Collectors.joining(", "));
            return String.format("[%s]", instrString);
        }
    }

    class ResultInstruction {
        final long instr_offset;
        final long instr_size;
        final String mnem;
        final String operands;
        final String registers_written;
        final String registers_read;
        final String results;
        final Object[] results_objects;
        String instruction_mode;

        ResultInstruction(Instruction instruction) {
            StringBuilder ops = new StringBuilder();
            StringBuilder regs_read = new StringBuilder();
            StringBuilder regs_written = new StringBuilder();
            StringBuilder res = new StringBuilder();

            this.results_objects = instruction.getResultObjects();
            this.instr_offset = instruction.getAddress().getOffset();
            this.instr_size = instruction.getLength();
            this.mnem = instruction.getMnemonicString();

            Register thumb_register = instruction.getRegister("TMode");
            if (thumb_register != null) {
                BigInteger thumb_val = instruction.getValue(thumb_register, false);
                this.instruction_mode = thumb_val.equals(BigInteger.ONE) ? "THUMB" : "NONE" ;
            } else {
                this.instruction_mode = "NONE";
            }
            Register vle_register = instruction.getRegister("vle");
            if (vle_register != null) {
                BigInteger vle_val = instruction.getValue(vle_register, false);
                this.instruction_mode = vle_val.equals(BigInteger.ONE) ? "VLE" : this.instruction_mode ;
            }

            for (int i = 0; i < instruction.getNumOperands(); i++) {
                ops.append(instruction.getDefaultOperandRepresentation​(i));
                if (i != instruction.getNumOperands() - 1) {
                    ops.append(",");
                }
                if (instruction.getOperandRefType(i) == RefType.READ) {
                    regs_read.append(instruction.getOpObjects(i)[instruction.getOpObjects(i).length-1].toString());
                    if (i != instruction.getNumOperands() - 1) {
                        regs_read.append(",");
                    }
                }
                if (instruction.getOperandRefType(i) == RefType.WRITE) {
                    regs_written.append(instruction.getOpObjects(i)[instruction.getOpObjects(i).length-1].toString());
                     if (i != instruction.getNumOperands() - 1) {
                        regs_written.append(",");
                    }
                }
                if (instruction.getOperandRefType(i) == RefType.READ_WRITE) {
                    regs_read.append(instruction.getOpObjects(i)[instruction.getOpObjects(i).length-1].toString());
                    regs_written.append(instruction.getOpObjects(i)[instruction.getOpObjects(i).length-1].toString());
                    if (i != instruction.getNumOperands() - 1) {
                        regs_read.append(",");
                        regs_written.append(",");
                    }
                }
            }
            for (int i = 0; i < results_objects.length; i++) {
                res.append(results_objects[i]);
                if (i != results_objects.length - 1) {
                    res.append(",");
                }
            }

            this.operands = ops.toString();
            this.registers_read = regs_read.toString();
            this.registers_written = regs_written.toString();
            this.results = res.toString();
        }

        String toJson() {
            return String.format("{\"instr_offset\":%d,\"instr_size\":%d,\"mnem\":\"%s\",\"operands\":\"%s\",\"regs_read\":\"%s\",\"regs_written\":\"%s\",\"results\":\"%s\",\"instr_mode\":\"%s\"}",
            instr_offset, instr_size, mnem, operands, registers_read, registers_written, results, instruction_mode);
        }
    }
}
