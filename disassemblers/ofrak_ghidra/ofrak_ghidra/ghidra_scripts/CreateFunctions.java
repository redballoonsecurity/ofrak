import java.util.*;
import ghidra.app.util.headless.HeadlessScript;
import ghidra.program.model.address.Address;
import ghidra.program.model.listing.*;
import ghidra.program.model.symbol.SourceType;
import ghidra.app.cmd.function.CreateFunctionCmd;
import ghidra.util.Msg;


public class CreateFunctions extends HeadlessScript {

    @Override
    public void run() throws Exception {
        String[] functionNames = getScriptArgs()[0].split(",");
        String[] functionAddresses = getScriptArgs()[1].split(",");
        Msg.info(this, "functionNames.length " + functionNames.length + " functionAddresses.length: " + functionAddresses.length);

        String functionName;
        Address functionAddress;
        Function curFunc;
        CreateFunctionCmd cmd;
        int renamed = 0, failed = 0;
        for (int i = 0; i < functionNames.length; i++){
            functionName = functionNames[i];
            functionAddress = toAddr(Long.parseLong(functionAddresses[i]));
            // Adding the following logging make ghidra hang when creating functions, for an unknown reason:
            // Msg.info(this, "function address: " + functionAddress + " functionName: " + functionName);

            curFunc = getFunctionAt(functionAddress);
            if (curFunc == null){
                disassemble(functionAddress);
                cmd = new CreateFunctionCmd(functionName, functionAddress, null, SourceType.USER_DEFINED);
                boolean funCreation= cmd.applyTo(currentProgram, monitor);
                if(!funCreation) {
                    failed++;
                    Msg.info(this, "Failed creating function at address: " + functionAddress + " name: " + functionName + ". Error message: " + cmd.getStatusMsg());
                    continue;
                }
            } else {
                curFunc.setName(functionName, SourceType.USER_DEFINED);
            }
            renamed++;
        }
        Msg.info(this, "Renamed: " + renamed + " failed: " + failed);
    }
}
