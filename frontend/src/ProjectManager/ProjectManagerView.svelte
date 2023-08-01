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
  .manager {
    width: 100%;
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
  .sub-title {
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
  import ProjectManagerToolbar from "./ProjectManagerToolbar.svelte";

  let focus,
    selectedBinary,
    selectedScript = null;

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
        id: $selectedProject.session_id,
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
<div class="hbox">
  <ProjectManagerToolbar
    bind:focus="{focus}"
    openProject="{openProject}"
    bind:showProjectManager="{showProjectManager}"
  />
  <div class="manager">
    <Split vertical="{true}" percentOfFirstSplit="{70}">
      <Split percentOfFirstSplit="{50}" slot="first">
        <Pane slot="first">
          <div class="sub-title">
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
          <div class="sub-title">
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
  </div>
</div>
