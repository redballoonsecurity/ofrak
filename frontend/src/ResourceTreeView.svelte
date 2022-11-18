<style>
  .hbox {
    display: flex;
    flex-direction: row;
    flex-wrap: nowrap;
    justify-content: flex-start;
    align-items: stretch;
    height: 100%;
    max-height: 100%;
  }

  .toolbar {
    position: sticky;
    top: 0;
    left: 0;
    padding-right: 1em;
    min-width: 18ch;
  }

  .hbox,
  .toolbar {
    overflow: auto;
    overflow-y: scroll;
  }

  .treebox {
    flex-grow: 1;
    padding-left: 1em;
    overflow-x: scroll;
    white-space: nowrap;
    text-align: left;
  }
</style>

<script>
  import ResourceTreeNode from "./ResourceTreeNode.svelte";
  import ResourceTreeToolbar from "./ResourceTreeToolbar.svelte";

  export let rootResource,
    modifierView,
    resourceNodeDataMap = {};
</script>

<div class="hbox">
  <div class="toolbar">
    <ResourceTreeToolbar
      bind:resourceNodeDataMap="{resourceNodeDataMap}"
      bind:modifierView="{modifierView}"
    />
  </div>

  <div class="treebox">
    <ResourceTreeNode
      rootResource="{rootResource}"
      bind:resourceNodeDataMap="{resourceNodeDataMap}"
    />
  </div>
</div>
