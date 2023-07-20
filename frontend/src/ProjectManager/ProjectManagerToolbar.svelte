<script>
  import ProjectManagerAddFileToProject from "./ProjectManagerAddFileToProject.svelte";
  import Toolbar from "../Toolbar.svelte";

  export let focus, openProject, showProjectManager;
  let toolbarButtons;

  toolbarButtons = [
    {
      text: "Back",
      iconUrl: "/icons/back-arrow.svg",
      shortcut: "b",
      onclick: async (e) => {
        showProjectManager = false;
      },
    },
    {
      text: "Run",
      iconUrl: "/icons/run.svg",
      shortcut: "r",
      onclick: openProject,
    },
    {
      text: "Add",
      iconUrl: "/icons/plus.svg",
      shortcut: "+",
      onclick: async (e) => {
        focus = ProjectManagerAddFileToProject;
      },
    },
  ];
</script>

<Toolbar toolbarButtons="{toolbarButtons}" />
