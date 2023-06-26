<style>
  select {
    background-color: var(--main-bg-color);
    color: inherit;
    border: 1px solid;
    border-color: inherit;
    border-radius: 0;
    font-size: inherit;
    font-family: var(--font);
    box-shadow: none;
  }

  input {
    background: inherit;
    color: inherit;
    border: 1px solid;
    border-bottom: 1px solid var(--main-fg-color);
    flex: 1;
  }

  form {
    display: inherit;
    flex: 1;
  }

  label {
    display: inherit;
    flex: 1;
  }

  .searchbar {
    display: flex;
    align-items: left;
    flex-grow: 1;
    height: 2em;
    width: 100%;
    position: sticky;
    padding-bottom: 1em;
  }

  .resultwidgets {
    display: flex;
  }

  .resultcount {
    margin-top: 0;
    margin-bottom: 0;
    border-style: solid;
    width: 100%;
    padding-left: 1em;
    padding-right: 1em;
  }

  button {
    height: 100%;
  }

  .optionbar {
    padding-bottom: 0;
    padding-top: 0;
  }
</style>

<script>
  import { selectedResource } from "./stores";
  import Checkbox from "./Checkbox.svelte";

  let searchType, searchQuery, bytesInput, regex, placeholderString, caseIgnore;
  let searchTypes = ["String", "Bytes"];
  export let rootResource, searchFilter;

  export let search, searchResults;

  searchResults.matches = undefined;
  searchResults.index = 0;

  let prevQuery = "";

  function nextMatch() {
    let nextIndex = searchResults.index + 1;
    if (nextIndex >= searchResults.matches.length) {
      nextIndex = 0;
    }
    searchResults = { matches: searchResults.matches, index: nextIndex };
  }

  function prevMatch() {
    let nextIndex = searchResults.index - 1;
    if (nextIndex < 0) {
      nextIndex = Math.max(searchResults.matches.length - 1, 0);
    }
    searchResults = { matches: searchResults.matches, index: nextIndex };
  }

  $: if (searchQuery && searchType === "Bytes") {
    try {
      searchQuery = searchQuery.match(/[0-9a-fA-F]{1,2}/g).join(" ");
      bytesInput?.setCustomValidity("");
    } catch {
      searchQuery = "";
      bytesInput?.setCustomValidity("Invalid bytes representation.");
    }
  }

  $: if (searchType == "String") {
    if (regex) {
      placeholderString = " Search for a Regex Pattern";
    } else {
      placeholderString = " Search for a String";
    }
  } else if (searchType == "Bytes") {
    regex = false; // Regex for bytes not yet implemented
    placeholderString = " Search for Bytes";
  }
</script>

<div class="searchbar">
  <select bind:value="{searchType}">
    {#each searchTypes as type}
      <option value="{type}">
        {type}
      </option>
    {/each}
  </select>
  <form
    on:submit|preventDefault="{async (e) => {
      if (searchQuery.length === 0) {
        searchResults.matches = undefined;
        prevQuery = '';
      } else if (searchQuery == prevQuery) {
        nextMatch();
      } else {
        searchResults.matches = await search(searchQuery, searchType);
        searchResults.index = 0;
        prevQuery = searchQuery;
      }
    }}"

    on:keyup|preventDefault="{async (e) => {
    searchResults.matches = await search(searchQuery, searchType);
    searchResults.index = 0;
    prevQuery = searchQuery;
    }}"
  >
    <label>
      <input placeholder="{placeholderString}" bind:value="{searchQuery}" />
    </label>
  </form>
  <div class="resultwidgets">
    {#if searchResults.matches !== undefined && searchResults.matches !== null}
      {#if searchResults.matches.length > 0}<p class="resultcount">
          {searchResults.index + 1}/{searchResults.matches.length}
        </p>
        <button on:click="{nextMatch}">↓</button>
        <button on:click="{prevMatch}">↑</button>
      {:else}
        <p class="resultcount">No match</p>
      {/if}
    {/if}
  </div>
</div>
<div class="optionbar">
  {#if searchType == "String"}
    <Checkbox checked="{caseIgnore}" bind:value="{regex}" leftbox="{true}">
      Pattern
    </Checkbox>
    <Checkbox checked="{false}" bind:value="{caseIgnore}" leftbox="{true}">
      Ignore Case
    </Checkbox>
  {/if}
</div>
