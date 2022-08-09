import ghidra.base.project.GhidraProject;

import ghidra.app.util.headless.HeadlessScript;

/*
 * Create a shared project
 *
 * analyzeHeadless . empty -postScript CreateProject.java -deleteProject -noanalysis
 *
*/

public class CreateRepository extends HeadlessScript {

    @Override
    public void run() throws Exception {
        setServerCredentials("root", "changeme");
        GhidraProject.getServerRepository("localhost", 13100, "ofrak", true);
    }
}
