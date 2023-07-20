<script>
  import ProjectManagerAddFileToProject from "./ProjectManagerAddFileToProject.svelte";
  import Toolbar from "../Toolbar.svelte";

  export let focus, openProject;
  let toolbarButtons;

  toolbarButtons = [
    {
      text: "Run Project",
      iconUrl: "/icons/run.svg",
      shortcut: "r",
      onclick: openProject,
    },
    {
      text: "Add File",
      iconUrl: "/icons/plus.svg",
      shortcut: "+",
      onclick: async (e) => {
        focus = ProjectManagerAddFileToProject;
      },
    },
  ];
</script>

<Toolbar toolbarButtons="{toolbarButtons}" />
