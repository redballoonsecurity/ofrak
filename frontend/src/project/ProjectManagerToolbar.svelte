<script>
  import { settings, selectedProject } from "../stores.js";
  import ProjectManagerAddBinaryToProject from "./ProjectManagerAddBinaryToProject.svelte";
  import ProjectManagerAddScriptToProject from "./ProjectManagerAddScriptToProject.svelte";
  import Toolbar from "../utils/Toolbar.svelte";

  export let focus, openProject, showProjectManager, forceRefreshProject;
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
      text: "Launch",
      iconUrl: "/icons/run.svg",
      shortcut: "l",
      onclick: openProject,
    },
    {
      text: "Add Binary",
      iconUrl: "/icons/binary.svg",
      shortcut: "B",
      onclick: async (e) => {
        focus = { object: ProjectManagerAddBinaryToProject, args: {} };
      },
    },
    {
      text: "Add Script",
      iconUrl: "/icons/document.svg",
      shortcut: "S",
      onclick: async (e) => {
        focus = { object: ProjectManagerAddScriptToProject, args: {} };
      },
    },
    {
      text: "Save",
      iconUrl: "/icons/disk.svg",
      shortcut: "s",
      onclick: async (e) => {
        await fetch(`${$settings.backendUrl}/save_project_data`, {
          method: "POST",
          body: JSON.stringify($selectedProject),
        });
      },
    },
    {
      text: "Reset",
      iconUrl: "/icons/reset.svg",
      shortcut: "R",
      onclick: async (e) => {
        await fetch(`${$settings.backendUrl}/reset_project`, {
          method: "POST",
          body: JSON.stringify({
            id: $selectedProject.session_id,
          }),
        }).then(async (r) => {
          if (!r.ok) {
            throw Error(JSON.stringify(await r.json(), undefined, 2));
          }
          $selectedProject = await fetch(
            `${$settings.backendUrl}/get_project_by_id?id=${$selectedProject.session_id}`
          ).then(async (r) => {
            if (!r.ok) {
              throw Error(JSON.stringify(await r.json(), undefined, 2));
            }
            return r.json();
          });
          forceRefreshProject = {};
          return await r.json();
        });
      },
    },
  ];
</script>

<Toolbar toolbarButtons="{toolbarButtons}" />
