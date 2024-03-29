<style>
  .container {
    min-height: 100%;
    display: flex;
    flex-direction: column;
    flex-wrap: nowrap;
    justify-content: center;
    align-items: stretch;
    align-content: center;
  }

  .inputs {
    flex-grow: 1;
  }

  .inputs *:first-child {
    margin-top: 0;
  }

  .actions {
    margin-top: 2em;
    display: flex;
    flex-direction: row;
    flex-wrap: nowrap;
    justify-content: space-evenly;
    align-items: flex-start;
    align-content: flex-start;
  }

  input {
    background: inherit;
    color: inherit;
    border: none;
    border-bottom: 1px solid white;
    flex-grow: 1;
    margin-left: 1ch;
  }

  input:focus {
    outline: none;
    box-shadow: inset 0 -1px 0 var(--main-fg-color);
  }

  label {
    margin-bottom: 1em;
    display: flex;
    flex-direction: row;
    flex-wrap: nowrap;
    justify-content: space-evenly;
    align-items: baseline;
    align-content: center;
    white-space: nowrap;
  }

  .row {
    display: flex;
    flex-direction: row;
    flex-wrap: nowrap;
    justify-content: space-evenly;
    align-items: baseline;
    align-content: center;
    white-space: nowrap;
  }

  .error {
    margin-top: 2em;
  }
</style>

<script>
  import { selectedResource, resourceNodeDataMap } from "../stores.js";
  import { calculator } from "../helpers";
  import ResourceTreeNode from "../resource/ResourceTreeNode.svelte";
  import Checkbox from "../utils/Checkbox.svelte";
  import Button from "../utils/Button.svelte";

  export let modifierView;
  let searchInput,
    searchRangeStartInput,
    searchRangeEndInput,
    rangeSearch = false,
    results = [],
    errorMessage;

  const searchTarget = $selectedResource;

  async function search() {
    if (searchTarget) {
      try {
        if (rangeSearch) {
          const searchRangeStartAddress = calculator.calculate(
              searchRangeStartInput
            ),
            searchRangeEndAddress = calculator.calculate(searchRangeEndInput);

          results = await searchTarget.search_for_vaddr(
            searchRangeStartAddress,
            searchRangeEndAddress
          );
        } else {
          const startAddress = calculator.calculate(searchInput);

          results = await searchTarget.search_for_vaddr(startAddress, null);
        }
      } catch (err) {
        try {
          errorMessage = JSON.parse(err.message).message;
        } catch (_) {
          errorMessage = err.message;
        }
      }
    }
  }

  async function leave_view() {
    if ($selectedResource !== undefined) {
      const ancestors = await $selectedResource.get_ancestors(null);
      for (const ancestor of ancestors) {
        $resourceNodeDataMap[ancestor.get_id()].collapsed = false;
      }
    }
    modifierView = undefined;
  }
</script>

<div class="container">
  <div class="inputs">
    <p>
      Searching for descendants of {searchTarget.get_caption()} ({searchTarget.get_id()})
      whose virtual address matches a specific address or lies in a range of
      addresses.
    </p>
    {#if rangeSearch}
      <label>
        Min virtual address:
        <input type="text" bind:value="{searchRangeStartInput}" />
      </label>
      <label>
        Max virtual address:
        <input type="text" bind:value="{searchRangeEndInput}" />
      </label>
    {:else}
      <label>
        Virtual address:
        <input type="text" bind:value="{searchInput}" />
      </label>
    {/if}
    <div class="row">
      <Checkbox bind:checked="{rangeSearch}">Range</Checkbox>
    </div>
    {#if errorMessage}
      <p class="error">
        Error:
        {errorMessage}
      </p>
    {/if}
  </div>
  <div class="actions">
    <Button on:click="{search}">Search</Button>
    <Button on:click="{leave_view}">Cancel</Button>
  </div>
  <div class="results">
    <p>Found {results.length} results</p>
  </div>
  {#each results as matched_resource}
    <div class="resultsbox">
      <ResourceTreeNode rootResource="{matched_resource}" collapsed="false" />
    </div>
  {/each}
</div>
