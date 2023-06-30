<style>
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
    margin-bottom: 1em;
    max-width: 100%;
    max-height: 100%;
    text-align: center;
  }

  .selectors {
    display: flex;
    align-items: stretch;
    justify-content: space-around;
    flex-direction: row;
    height: 50vh;
  }
  .options {
    display: flex;
    align-items: stretch;
    justify-content: space-around;
    flex-direction: row;
    height: 30vh;
  }
</style>

<script>
  import ProjectManagerOptions from "./ProjectManagerOptions.svelte";
  import ProjectManagerSelector from "./ProjectManagerSelector.svelte";

  export let project;
  let focus, selectedBinary, selectedScript;
</script>

<div class="vbox">
  <div class="title">OFRAK Project Manager</div>
  <div class="selectors">
    <ProjectManagerSelector
      title="Binaries"
      projectElementOptions="{project.binaries}"
      selection="{selectedBinary}"
      bind:focus="{focus}"
    />
    <ProjectManagerSelector
      title="Scripts"
      projectElementOptions="{project.scripts}"
      selection="{selectedScript}"
      bind:focus="{focus}"
    />
    <ProjectManagerSelector
      title="Components"
      projectElementOptions="{project.components}"
      bind:focus="{focus}"
    />
  </div>
  <div class="options">
    <ProjectManagerOptions focus="{focus}" />
  </div>
</div>
