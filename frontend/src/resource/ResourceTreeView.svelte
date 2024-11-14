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
    overflow: auto;
  }

  .treebox {
    flex-grow: 1;
    padding-left: 1em;
    white-space: nowrap;
    text-align: left;
  }

  .searchbar {
    flex-grow: 1;
    padding-left: 1em;
    padding-right: 1em;
    padding-bottom: 0.5em;
    position: sticky;
    top: 0;
    background-color: var(--main-bg-color);
    z-index: 10;
  }
</style>

<script>
  import SearchBar from "../utils/SearchBar.svelte";
  import ResourceTreeNode from "./ResourceTreeNode.svelte";
  import ResourceTreeToolbar from "./ResourceTreeToolbar.svelte";

  export let rootResource,
    modifierView,
    bottomLeftPane,
    showProjectManager,
    showRootResource;

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
    return searchFilter;
  }
</script>

<div class="hbox">
  <div class="toolbar">
    <ResourceTreeToolbar
      bind:modifierView="{modifierView}"
      bind:bottomLeftPane="{bottomLeftPane}"
      bind:showProjectManager="{showProjectManager}"
      bind:showRootResource="{showRootResource}"
    />
  </div>
  <div class="resources">
    <div class="searchbar">
      <SearchBar
        search="{searchTreeForData}"
        liveUpdate="{true}"
        showResultsWidgets="{false}"
        bind:searchResults="{searchResults}"
      />
    </div>
    <div class="treebox">
      <ResourceTreeNode
        rootResource="{rootResource}"
        bind:searchResults="{searchResults}"
      />
    </div>
  </div>
</div>
