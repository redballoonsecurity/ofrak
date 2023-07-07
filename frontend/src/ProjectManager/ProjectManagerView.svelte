<style>
  button {
    padding-top: 0.5em;
    padding-bottom: 0.5em;
    padding-left: 1em;
    padding-right: 1em;
    border-radius: 1em;
  }
  .vbox {
    width: auto;
    height: auto;
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

  .selectors {
    display: flex;
    align-items: stretch;
    justify-content: space-around;
    flex-direction: row;
    height: 55vh;
  }
  .options {
    display: flex;
    align-items: stretch;
    justify-content: space-around;
    flex-direction: row;
    height: 25vh;
    margin-top: 1em;
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
  import ProjectManagerOptions from "./ProjectManagerOptions.svelte";
  import ProjectManagerSelector from "./ProjectManagerSelector.svelte";

  export let project;
  let focus, selectedBinary, selectedScript;

  function openProject() {}
</script>

<div class="vbox">
  <div class="title">OFRAK Project Manager</div>
  <div class="selectors">
    <ProjectManagerSelector
      title="Binaries"
      description="Select a binary for OFRAK to analyze."
      projectElementOptions="{project.binaries}"
      selection="{selectedBinary}"
      bind:focus="{focus}"
    />
    <ProjectManagerSelector
      title="Scripts"
      description="Select a script to analyze your binary with."
      projectElementOptions="{project.scripts}"
      selection="{selectedScript}"
      bind:focus="{focus}"
    />
    <ProjectManagerSelector
      title="Components"
      description="Select OFRAK Components to be included in your OFRAK instance."
      projectElementOptions="{project.components}"
      bind:focus="{focus}"
    />
  </div>
  <div class="options">
    <ProjectManagerOptions focus="{focus}" />
  </div>
  <div class="toolbar">
    <button on:click="{openProject}">Open Project</button>
  </div>
</div>
