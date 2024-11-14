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
    min-width: 15%;
  }

  .script {
    max-width: 85%;
    min-width: 85%;
  }
</style>

<script>
  import { selectedProject, settings, selected } from "../stores";
  import Script from "../utils/Script.svelte";
  import Toolbar from "../utils/Toolbar.svelte";
  import LoadingAnimation from "../utils/LoadingAnimation.svelte";

  export let args;
  let showScriptPromise = new Promise(() => {});

  async function deleteScript() {
    await fetch(`${$settings.backendUrl}/delete_script_from_project`, {
      method: "POST",
      headers: {
        "Content-Type": "application/json",
      },
      body: JSON.stringify({
        id: $selectedProject.session_id,
        script: args.name,
      }),
    }).then(async (r) => {
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

  $: showScriptPromise = fetch(
    `${$settings.backendUrl}/get_project_script?project=${$selectedProject.session_id}&script=${args.name}`
  ).then(async (r) => {
    if (!r.ok) {
      throw Error(r.statusText);
    }
    return (await r.text()).split("\n");
  });

  let toolbarButtons = [
    {
      text: "Delete Script",
      iconUrl: "/icons/trash.svg",
      shortcut: "D",
      onclick: () => {
        deleteScript;
      },
    },
  ];
</script>

<div class="hbox">
  <div class="toolbar">
    <Toolbar toolbarButtons="{toolbarButtons}" />
  </div>
  <div class="script">
    {#await showScriptPromise}
      <LoadingAnimation />
    {:then loadedScript}
      <Script script="{loadedScript}" />
    {/await}
  </div>
</div>
