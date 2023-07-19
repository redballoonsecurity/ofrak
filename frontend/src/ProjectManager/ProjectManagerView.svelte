<style>
  button {
    padding: 0.5em, 1em;
    border-radius: 1em;
  }
  .title {
    text-transform: uppercase;
    font-weight: bold;
    color: inherit;
    font-size: xxx-large;
    line-height: 1;
    margin: 0;
    max-width: 100%;
    max-height: 100%;
    text-align: center;
  }
  .toolbar {
    display: flex;
    justify-content: space-around;
    flex-direction: row;
    height: 5vh;
    margin-top: 1em;
  }
  .title {
    padding-bottom: 0.5em;
    text-align: center;
    font-size: xx-large;
    font-weight: bold;
    text-transform: uppercase;
  }
</style>

<script>
  import Pane from "../Pane.svelte";
  import Split from "../Split.svelte";
  import ProjectManagerAddFileToProject from "./ProjectManagerAddFileToProject.svelte";
  import ProjectManagerFocusableLabel from "./ProjectManagerFocusableLabel.svelte";
  import ProjectManagerOptions from "./ProjectManagerOptions.svelte";
  import ProjectManagerSelector from "./ProjectManagerSelector.svelte";
  import { selectedProject, settings, selected } from "../stores";
  import { remote_model_to_resource } from "../ofrak/remote_resource";

  let focus, selectedBinary, selectedScript;

  export let resources,
    rootResourceLoadPromise,
    rootResource,
    showRootResource,
    showProjectManager;

  async function openProject() {
    let rootModel = await fetch(`${$settings.backendUrl}/open_project`, {
      method: "POST",
      headers: {
        "Content-Type": "application/json",
      },
      body: JSON.stringify({
        id: $selectedProject.id,
        binary: selectedBinary,
        script: selectedScript,
      }),
    }).then((r) => r.json());
    rootResource = remote_model_to_resource(rootModel, resources);
    $selected = rootModel.id;
    showProjectManager = false;
    showRootResource = true;
  }
  $: rootResourceLoadPromise = openProject;
</script>

<div class="title">OFRAK Project Manager</div>
<button on:click|stopPropagation="{openProject}">Run Project</button>
<Split vertical="{true}" percentOfFirstSplit="{70}">
  <Split percentOfFirstSplit="{50}" slot="first">
    <Pane slot="first">
      <div class="title">
        <ProjectManagerFocusableLabel
          bind:focus="{focus}"
          label="Binaries"
          newFocus="{ProjectManagerAddFileToProject}"
        />
      </div>
      <ProjectManagerSelector
        projectElementOptions="{$selectedProject.binaries}"
        bind:selection="{selectedBinary}"
        bind:focus="{focus}"
      />
    </Pane>
    <Pane slot="second">
      <div class="title">
        <ProjectManagerFocusableLabel
          bind:focus="{focus}"
          label="Scripts"
          newFocus="{ProjectManagerAddFileToProject}"
        />
      </div>
      <ProjectManagerSelector
        projectElementOptions="{$selectedProject.scripts}"
        bind:selection="{selectedScript}"
        bind:focus="{focus}"
      />
    </Pane>
  </Split>
  <Pane slot="second" paddingVertical="{'1em'}">
    <ProjectManagerOptions focus="{focus}" />
  </Pane>
</Split>
<div class="toolbar">
  <button on:click="{openProject}">Open Project</button>
</div>
