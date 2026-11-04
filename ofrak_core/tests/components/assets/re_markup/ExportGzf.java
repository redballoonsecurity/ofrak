import ghidra.app.script.GhidraScript;
import ghidra.app.util.exporter.GzfExporter;
import java.io.File;

// Export the current program as a Ghidra Zip File (.gzf), the format the OFRAK Ghidra backend
// loads with GhidraProjectConfig. Usage: -postScript ExportGzf.java OUTPUT.gzf
public class ExportGzf extends GhidraScript {
    @Override
    public void run() throws Exception {
        File output = new File(getScriptArgs()[0]);
        GzfExporter exporter = new GzfExporter();
        // Packing the program needs a lock, which the script's own transaction would prevent
        end(false);
        try {
            if (!exporter.export(output, currentProgram, null, monitor)) {
                throw new RuntimeException("Could not export " + output + ": " + exporter.getMessageLog());
            }
        } finally {
            start();
        }
    }
}
