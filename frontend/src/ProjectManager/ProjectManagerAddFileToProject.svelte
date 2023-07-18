<script>
  import FileBrowser from "../FileBrowser.svelte";
  import { selectedProject, settings } from "../stores";
  let files, f;
  let dataPromise = new Promise(() => {});

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

  async function addScriptToProject(name, data) {
    data = await dataPromise;
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

<FileBrowser bind:files="{files}" />
{#if f}
  <button on:click="{addBinaryToProject}"
    >Add {f.name}[{f.size}B] to Project as Binary</button
  >
  <button on:click="{addScriptToProject}"
    >Add {f.name}[{f.size}B] to Project as Script</button
  >
{/if}
