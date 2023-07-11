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
</style>

<script>
  import Pane from "../Pane.svelte";
  import Split from "../Split.svelte";
  import ProjectManagerOptions from "./ProjectManagerOptions.svelte";
  import ProjectManagerSelector from "./ProjectManagerSelector.svelte";

  export let project;
  let focus, selectedBinary, selectedScript;

  function openProject() {}
</script>

<div class="title">OFRAK Project Manager</div>
<Split vertical="{true}" percentOfFirstSplit="{70}">
  <Split percentOfFirstSplit="{50}" slot="first">
    <Pane slot="first">
      <ProjectManagerSelector
        title="Binaries"
        description="Select a binary for OFRAK to analyze."
        projectElementOptions="{project.binaries}"
        selection="{selectedBinary}"
        bind:focus="{focus}"
      />
    </Pane>
    <Pane slot="second">
      <ProjectManagerSelector
        title="Scripts"
        description="Select a script to analyze your binary with."
        projectElementOptions="{project.scripts}"
        selection="{selectedScript}"
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
