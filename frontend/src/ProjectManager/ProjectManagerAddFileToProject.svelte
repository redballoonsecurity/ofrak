<style>
  .add-file {
    display: flex;
    flex-direction: row;
  }
</style>

<script>
  import FileBrowser from "../FileBrowser.svelte";
  import { selectedProject, settings } from "../stores";
  let files, f;

  $: if (files) {
    f = files[0];
    files = null;
  }
  async function addBinaryToProject() {
    await fetch(
      `${$settings.backendUrl}/add_binary_to_project?id=${$selectedProject.id}&name=${f.name}`,
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
        `${$settings.backendUrl}/get_project_by_id?id=${$selectedProject.id}`
      ).then((r) => {
        if (!r.ok) {
          throw Error(r.statusText);
        }
        return r.json();
      });
      console.log($selectedProject);
      return await r.json();
    });
  }

  async function addScriptToProject() {
    return await fetch(
      `${$settings.backendUrl}/add_script_to_project?id=${$selectedProject.id}&name=${f.name}`,
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
        `${$settings.backendUrl}/get_project_by_id?id=${$selectedProject.id}`
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
    {f.name}[{f.size}B]
    <button on:click="{addBinaryToProject}">Add to Project as Binary</button>
    <button on:click="{addScriptToProject}">Add to Project as Script</button>
  {/if}
</div>
