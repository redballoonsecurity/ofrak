import ghidra.app.script.GhidraScript;
import ghidra.program.model.mem.*;
import ghidra.program.model.lang.*;
import ghidra.program.model.pcode.*;
import ghidra.program.model.util.*;
import ghidra.program.model.reloc.*;
import ghidra.program.model.data.*;
import ghidra.program.model.block.*;
import ghidra.program.model.symbol.*;
import ghidra.program.model.scalar.*;
import ghidra.program.model.listing.*;
import ghidra.program.model.address.*;

import java.math.BigInteger;

public class PreAnalyzePPCVLE extends GhidraScript {

    @Override
    public void run() throws Exception {
        try {
            // Set the language to PPC VLE
            Language language = (Language) getLanguage(new LanguageID("PowerPC:BE:64:VLE-32addr"));
            Program p = currentProgram;
            p.setLanguage(language, language.getDefaultCompilerSpec().getCompilerSpecID(), false, monitor);
            ProgramContext programContext = p.getProgramContext();
            // Set the vle bit (Ghidra has a "vle" register for that, but on real devices, the VLE
            // bit is defined per memory page, as a page attribute bit) so that instructions are
            // decoded correctly.
            for (Register register : programContext.getContextRegisters()) {
                if (register.getName().equals("vle")){
                    RegisterValue newValue = new RegisterValue(programContext.getBaseContextRegister());
                    BigInteger value = BigInteger.ONE;
                    newValue = setRegisterValue(newValue, register, value);
                    programContext.setDefaultDisassemblyContext(newValue);
                    println("Set the vle bit.");
                }
            }
        } catch(Exception e) {
            println(e.toString());
            e.printStackTrace(System.out);
            throw e;
        }
    }

    private RegisterValue setRegisterValue(RegisterValue registerValue, Register register,
           BigInteger value) {
        RegisterValue newValue = new RegisterValue(register, value);
        return registerValue.combineValues(newValue);
    }

}
