<style>
  .add-file {
    display: flex;
    flex-direction: row;
    justify-content: space-around;
  }
</style>

<script>
  import FileBrowser from "../utils/FileBrowser.svelte";
  import Icon from "../utils/Icon.svelte";
  import Button from "../utils/Button.svelte";
  import { selectedProject, settings } from "../stores";
  let files, f;

  $: if (files) {
    f = files[0];
    files = null;
  }

  async function addScriptToProject() {
    return await fetch(
      `${$settings.backendUrl}/add_script_to_project?id=${$selectedProject.session_id}&name=${f.name}`,
      {
        method: "POST",
        headers: {
          "Content-Type": "application/json",
        },
        body: await f.arrayBuffer(),
      }
    ).then(async (r) => {
      if (!r.ok) {
        throw Error(JSON.stringify(await r.json(), undefined, 2));
      }
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
</script>

<div class="add-file">
  <FileBrowser bind:files="{files}" />
  {#if f}
    <Button on:click="{addScriptToProject}"
      ><Icon url="/icons/document.svg" /> Add Script to Project</Button
    >
  {/if}
</div>
