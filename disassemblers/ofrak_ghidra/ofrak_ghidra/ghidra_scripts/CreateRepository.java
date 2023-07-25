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
        String[] args = getScriptArgs();
        setServerCredentials(args[0], args[1]);
        GhidraProject.getServerRepository(args[2], Integer.parseInt(args[3]), "ofrak", true);
    }
}
