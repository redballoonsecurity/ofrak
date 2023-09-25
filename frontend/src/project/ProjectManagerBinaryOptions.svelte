<style>
  .hbox {
    display: flex;
    flex-direction: row;
    flex-wrap: nowrap;
    justify-content: flex-start;
    width: 100%;
    height: 100%;
    max-height: 100%;
  }

  .toolbar {
    max-width: 15%;
  }
</style>

<script>
  import { selectedProject, settings, selected } from "../stores";
  import Toolbar from "../Toolbar.svelte";
  import Button from "../utils/Button.svelte";

  export let args, selectedBinaryName, forceRefreshProject;

  async function deleteBinary() {
    await fetch(`${$settings.backendUrl}/delete_binary_from_project`, {
      method: "POST",
      headers: {
        "Content-Type": "application/json",
      },
      body: JSON.stringify({
        id: $selectedProject.session_id,
        binary: args.name,
      }),
    }).then(async (r) => {
      if (!r.ok) {
        throw Error(JSON.stringify(await r.json(), undefined, 2));
      }
      selectedBinaryName = undefined;
      forceRefreshProject = {};
      $selectedProject = await fetch(
        `${$settings.backendUrl}/get_project_by_id?id=${$selectedProject.session_id}`
      ).then((r) => {
        if (!r.ok) {
          throw Error(r.statusText);
        }
        return r.json();
      });
      return await r.json();
    });
  }

  let toolbarButtons = [
    {
      text: "Delete Binary",
      iconUrl: "/icons/trash.svg",
      shortcut: "D",
      onclick: () => {
        deleteBinary;
      },
    },
  ];
</script>

<div class="hbox">
  <div class="toolbar">
    <Toolbar toolbarButtons="{toolbarButtons}" />
  </div>
</div>
