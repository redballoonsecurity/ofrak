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

  .toolbar {
    overflow: auto;
    overflow-y: scroll;
  }

  .hbox {
    overflow: auto;
  }

  .resources {
    flex-grow: 1;
  }

  .treebox {
    flex-grow: 1;
    padding-left: 1em;
    overflow-x: auto;
    white-space: nowrap;
    text-align: left;
  }

  .searchbar {
    flex-grow: 1;
    padding-left: 1em;
    padding-bottom: 0.5em;
  }
</style>

<script>
  import ResourceSearchBar from "./ResourceSearchBar.svelte";
  import ResourceTreeNode from "./ResourceTreeNode.svelte";
  import ResourceTreeToolbar from "./ResourceTreeToolbar.svelte";

  export let rootResource,
    modifierView,
    bottomLeftPane,
    resourceNodeDataMap = {};

  let searchFilter;
  let searchResults = {};

  async function searchTreeForData(searchQuery, options) {
    if (searchQuery === "") {
      searchFilter = null;
    }
    if (options.searchType === "String") {
      searchFilter = await rootResource.search_for_string(searchQuery, options);
    } else if (options.searchType === "Bytes") {
      searchFilter = await rootResource.search_for_bytes(searchQuery, false);
    }

    return { matches: searchFilter, index: 0 };
  }
</script>

<div class="hbox">
  <div class="toolbar">
    <ResourceTreeToolbar
      bind:resourceNodeDataMap="{resourceNodeDataMap}"
      bind:modifierView="{modifierView}"
      bind:bottomLeftPane="{bottomLeftPane}"
    />
  </div>
  <div class="resources">
    <div class="searchbar">
      <ResourceSearchBar
        search="{searchTreeForData}"
        liveUpdate="{true}"
        showResultsWidgets="{false}"
        bind:searchResults="{searchResults}"
      />
    </div>
    <div class="treebox">
      <ResourceTreeNode
        rootResource="{rootResource}"
        bind:searchFilter="{searchFilter}"
        bind:resourceNodeDataMap="{resourceNodeDataMap}"
      />
    </div>
  </div>
</div>
