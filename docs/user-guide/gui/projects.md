# Projects
Projects are OFRAK's way of saving, organizing, and sharing your work. Projects are collections of binaries and scripts along with metadata that describes relationships between them.

## The Interface
The Project Options interface is available from the start menu and gives you three options for opening a project. The "Create New Project" opens up a blank project, "Open Existing Project" will open a project already in your Project Path, and "Clone Project from Git" clones the URL provided to your Project Path. The Project Path, where all of the projects are saved to and loaded from, may be modified in the Advanced Options section of the Project Options interface. 

![](assets/project-options.png)

The OFRAK Project Manager interface is loaded upon opening a project and displays the structure of the project along with options to modify it. The Binaries panel displays each binary in the project. Select a binary to work with by clicking on its name. The Script panel shows options for each script in your project. Upon selecting a binary, two checkboxes options appear for each script. Hovering over each checkbox describes its function. One check box selects whether the script is compatible with the currently selected binary, allowing access to it in the Run Script option of the OFRAK Resource toolbar. The second checkbox selects a script to be run upon entering the OFRAK Resource interface, giving a starting point for exploration.

![](assets/project-manager.png)

## Creating a Project
OFRAK projects should be initialized through the OFRAK Project Manager to ensure a correcting project structure. Binaries and scripts are added to the project thorugh the corresponding toolbar options on the left side of the interface. After adding your assets, use the checkboxes in the script panel to link scripts with their binaries. The Save option in the toolbar will save your project, and reset will go back to the previously saved state.

## Launching a Project Binary
Binaries from projects can be launched from the Launch option of the toolbar. When launched, the selected script will run on the binary and then display the result in the OFRAK Resource interface. 
![](assets/project-launch.gif)


## Sharing Work
Projects make it easy to share your work with others. Git integration allows users to easily clone public repos into their Project Path and follow the process used by others in OFRAK. Check out Red Balloon's [Example Project](https://github.com/redballoonsecurity/ofrak-project-example) to get started!

<!-- # OFRAK Projects
OFRAK Projects are collections of binaries and scripts that can be run automatically through the OFRAK GUI. Projects can be useful tools for documenting past work, sharing work, and collaborating with other OFRAK users. 

## Opening an OFRAK Project
New or existing OFRAK Projects can be opened by the Project Options button on the front page of the OFRAK GUI. Selecting the OFRAK Project Options will open up the Projects Options view. From here you can either create a new OFRAK Project, open an existing OFRAK Project, clone an OFRAK Project from Github, or change the Project Path.

### Create a New OFRAK Project
When you elect to create a new OFRAK Project, all you will need to enter is a name. This name can be used to re-open the project later on or find it in your Project Path. Type in your name, push the Create New Project button and you're ready to build your new OFRAK Project.

### Clone an OFRAK Project from Github
You can also clone an OFRAK Project from Github directly into your Project Path using the Clone Project from Git button. If another user has a properly created OFRAK project up on Github, you can paste the URL into the Git URL field and clone the project directly into your Project Path. 

### Open Existing OFRAK Project
After you have created or cloned an OFRAK Project, you can re-open the project through the Open Existing Project option. The drop down menu contains a list of all OFRAK Projects in your Project Path, keyed by name and unique session ID. You might want to have multiple instances of the same project open so take note of which session ID corresponds to the project you want to open. 

### OFRAK Project Path
The OFRAK Project Path is the location where the OFRAK server will look for your projects. These projects can be loaded by the methods above, or simply copied into the specified Project Path directory on the host. By default the Project Path is `/tmp/ofrak-projects` but can be changed in the Advanced Options of the Project Options view. To change the Project Path, tick the Advanced Options checkbox to reveal the Project Path input. Type in your Project Path and press Set Location. Your Existing Projects drop down should update to the new location's projects.

## OFRAK Project Interface
The OFRAK Project Interface is the primary way to inspect, modify, and load projects into the OFRAK GUI. It contains a Toolbar and three panels. Two of the panels display your scripts and binaries, and the third will display various options. 

### Loading a Project


### Binaries
The binari

### Scripts

### Toolbar
The OFRAK Project Toolbar 

### Options -->