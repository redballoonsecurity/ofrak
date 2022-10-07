<style>
  button {
    padding-top: 0.5em;
    padding-bottom: 0.5em;
    padding-left: 1em;
    padding-right: 1em;
  }

  button:hover,
  button:focus {
    outline: none;
    box-shadow: inset 1px 1px 0 var(--main-fg-color),
      inset -1px -1px 0 var(--main-fg-color);
  }

  button:active {
    box-shadow: inset 2px 2px 0 var(--main-fg-color),
      inset -2px -2px 0 var(--main-fg-color);
  }

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
    align-items: center;
    align-content: center;
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

  /* Adapted from: https://moderncss.dev/pure-css-custom-checkbox-style/ */
  input[type="checkbox"] {
    flex-grow: 0;
    margin-left: 1ch;
    /*
    appearance: none;
    background-color: var(--main-bg-color);
    margin: 0;
    color: currentColor;
    width: 1em;
    height: 1em;
    border: 1px solid currentColor;
    display: grid;
    place-content: center;
    */
  }

  /*
  input[type="checkbox"]:focus {
    box-shadow: none;
  }

  input[type="checkbox"]::before {
    content: "";
    width: 0.45em;
    height: 0.45em;
    transform: scale(0);
    transition: 120ms transform ease-in-out;
    box-shadow: inset 1em 1em var(--main-fg-color);
  }

  input[type="checkbox"]:checked::before {
    transform: scale(1);
  }
  */

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
  import {selected, selectedResource} from "./stores.js";
  import {calculator} from "./helpers";

  export let modifierView;
  let searchInput,
    searchRangeStartInput,
    searchRangeEndInput,
    rangeSearch = false,
          results = [],
    errorMessage;

  function refreshResource() {
    // Force hex view refresh with colors
    const originalSelected = $selected;
    $selected = undefined;
    $selected = originalSelected;
  }

  async function search() {
    if ($selectedResource) {
      try {
        if (rangeSearch) {
          const searchRangeStartAddress = calculator.calculate(
                  searchRangeStartInput
          ),
                  searchRangeEndAddress = calculator.calculate(searchRangeEndInput);

          results = await $selectedResource.search_for_vaddr(searchRangeStartAddress, searchRangeEndAddress);
        } else {
          const startAddress = calculator.calculate(searchInput);

          results = await $selectedResource.search_for_vaddr(startAddress, null);
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
</script>

<div class="container">
  <div class="inputs">
    <p>
      Search for resources whose virtual address matches a specific address or
      lies in a range of addresses.
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
      <label>
        Range
        <input type="checkbox" bind:checked="{rangeSearch}" />
      </label>
    </div>
    {#if errorMessage}
      <p class="error">
        Error:
        {errorMessage}
      </p>
    {/if}
  </div>
  <div class="actions">
    <button on:click="{search}">Search</button>
    <button on:click="{() => (modifierView = undefined)}">Cancel</button>
  </div>
  <div class="results">
    <p>Found {results.length} results</p>
  </div>
</div>
