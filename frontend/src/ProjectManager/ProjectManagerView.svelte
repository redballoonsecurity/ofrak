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
  import ProjectManagerFocusableLabel from "./ProjectManagerFocusableLabel.svelte";
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
      <div class="title">
        <ProjectManagerFocusableLabel
          bind:focus="{focus}"
          label="Binaries"
          newFocus="Binaries"
        />
      </div>
      <ProjectManagerSelector
        projectElementOptions="{project.binaries}"
        selection="{selectedBinary}"
        bind:focus="{focus}"
      />
    </Pane>
    <Pane slot="second">
      <div class="title">
        <ProjectManagerFocusableLabel
          bind:focus="{focus}"
          label="Scripts"
          newFocus="Scripts"
        />
      </div>
      <ProjectManagerSelector
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
