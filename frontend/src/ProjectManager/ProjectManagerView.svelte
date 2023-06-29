<style>
  .vbox {
    width: 100%;
    height: 100%;
  }

  .title {
    text-transform: uppercase;
    font-weight: bold;
    color: inherit;
    font-size: xxx-large;
    line-height: 1;
    margin: 0;
    padding-bottom: 1em;
    max-width: 100%;
    max-height: 100%;
    text-align: center;
  }

  .manager {
    display: flex;
    align-items: stretch;
    justify-content: space-around;
    flex-direction: row;
    width: 100%;
    height: 100%;
  }

  .view {
    padding-left: 1em;
    text-align: center;
    font-size: x-large;
    font-weight: bold;
    text-transform: uppercase;
    width: 100%;
    height: 100%;
  }

  .box {
    outline: solid 1px var(--main-fg-color);
    border-radius: 5%;
    padding-top: 1em;
    width: 100%;
    height: 100%;
  }
</style>

<script>
  import ProjectManagerBinariesView from "./ProjectManagerBinariesView.svelte";
  import ProjectManagerComponentsView from "./ProjectManagerComponentsView.svelte";
  import ProjectManagerReadmeView from "./ProjectManagerReadmeView.svelte";
  import ProjectManagerScriptsView from "./ProjectManagerScriptsView.svelte";
</script>

<div class="vbox">
  <div class="title">OFRAK Project Manager</div>
  <div class="manager">
    <div class="view">
      Binaries
      <div class="box">
        <ProjectManagerBinariesView />
      </div>
    </div>
    <div class="view">
      Scripts
      <div class="box">
        <ProjectManagerScriptsView />
      </div>
    </div>
    <div class="view">
      Components
      <div class="box">
        <ProjectManagerComponentsView />
      </div>
    </div>
    <div class="view">
      Documentation
      <div class="box">
        <ProjectManagerReadmeView />
      </div>
    </div>
  </div>
</div>
