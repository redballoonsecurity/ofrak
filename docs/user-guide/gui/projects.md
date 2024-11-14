# Projects
Projects are OFRAK's way of saving, organizing, and sharing your work. Projects are collections of binaries and scripts, along with metadata that describes relationships between them.

## The Interface
The Project Options interface is available from the start menu and gives you three options for opening a project. The "Create New Project" opens up a blank project, "Open Existing Project" will open a project already in your Project Path, and "Clone Project from Git" clones the URL provided to your Project Path. The Project Path, where all of the projects are saved to and loaded from, may be modified in the Advanced Options section of the Project Options interface.

![](assets/project-options.png)

The OFRAK Project Manager interface is loaded upon opening a project and displays the structure of the project along with options to modify it. The Binaries panel displays each binary in the project. Select a binary to work with by clicking on its name. The Script panel shows options for each script in your project. Upon selecting a binary, two checkboxes options appear for each script. Hovering over each checkbox describes its function. One check box selects whether the script can be run on the currently selected binary, allowing access to it in the Run Script option of the OFRAK Resource toolbar. The second checkbox selects a script to be run upon entering the OFRAK Resource interface, giving a starting point for exploration.

![](assets/project-manager.png)

## Creating a Project
OFRAK projects should be initialized through the OFRAK Project Manager to ensure a correct project structure. Binaries and scripts are added to the project through the corresponding toolbar options on the left side of the interface. After adding your assets, use the checkboxes in the script panel to link scripts with their binaries. The Save option in the toolbar will save your project, and Reset will go back to the previously saved state.

## Launching a Project Binary
Binaries from projects can be launched from the Launch option of the toolbar. When launched, the selected binary's init script (marked by the second checkbox) will run on the binary and then display the result in the OFRAK Resource interface.
![](assets/project-launch.gif)


## Sharing Work
Projects make it easy to share your work with others. Git integration allows users to easily clone public repos and follow the process used by others in OFRAK. Check out Red Balloon's [Example Project](https://github.com/redballoonsecurity/ofrak-project-example) to get started!
