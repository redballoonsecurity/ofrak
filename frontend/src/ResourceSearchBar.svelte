<style>
  select {
    background-color: var(--main-bg-color);
    color: inherit;
    border: 1px solid var(--main-fg-color);
    border-radius: 0;
    font-size: inherit;
    font-family: var(--font);
    box-shadow: none;
  }

  select:focus {
    outline: none;
    box-shadow: inset 0 -1px 0 var(--main-fg-color);
  }

  input {
    background: inherit;
    color: inherit;
    border: 1px solid var(--main-fg-color);
    flex-grow: 1;
    text-indent: 0.5em;
  }

  form {
    flex-grow: 1;
    display: flex;
    margin-left: -1px;
  }

  label {
    flex-grow: 1;
    display: flex;
  }

  .searchbar {
    display: flex;
    align-items: left;
    flex-grow: 1;
    height: fit-content;
    width: 100%;
    padding-bottom: 1em;
    min-height: 2.25em;
  }

  .resultwidgets {
    display: flex;
    margin-left: -1px;
  }

  .resultcount {
    margin-top: 0;
    margin-bottom: 0;
    border: 1px solid var(--main-fg-color);
    width: 100%;
    padding-left: 1em;
    padding-right: 1em;
    padding-top: 0.25em;
  }

  button {
    height: 100%;
    margin-left: -1px;
  }

  .optionbar {
    padding-bottom: 0;
    padding-top: 0.25em;
    border: 1px solid var(--main-fg-color);
    padding-left: 1em;
    padding-right: 1em;
    margin-left: -1px;
  }
</style>

<script>
  import Checkbox from "./Checkbox.svelte";

  let searchQuery, bytesInput, placeholderString, errorMessage;
  let searchOptions = {
    searchType: "String",
    regex: false,
    caseIgnore: false,
  };
  const searchTypes = ["String", "Bytes"];

  export let search, searchResults, liveUpdate, showResultsWidgets;

  searchResults.matches = undefined;
  searchResults.index = 0;

  let prevQuery = "",
    prevOptions = {};

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

  function isRepeatedQuery() {
    return (
      searchQuery == prevQuery &&
      searchOptions.searchType == prevOptions.searchType &&
      searchOptions.regex == prevOptions.regex &&
      searchOptions.caseIgnore == prevOptions.caseIgnore
    );
  }

  async function doSearch() {
    try {
      searchResults.matches = await search(searchQuery, searchOptions);
    } catch (err) {
      try {
        errorMessage = JSON.parse(err.message).message;
      } catch (_) {
        errorMessage = err.message;
      }
      console.error("Search Failed!", errorMessage);
    }
    searchResults.index = 0;
    prevQuery = searchQuery;
    prevOptions = { ...searchOptions };
  }

  $: if (searchQuery && searchOptions.searchType === "Bytes") {
    try {
      searchQuery = searchQuery.match(/[0-9a-fA-F]{1,2}/g).join(" ");
      bytesInput?.setCustomValidity("");
    } catch {
      searchQuery = "";
      bytesInput?.setCustomValidity("Invalid bytes representation.");
    }
  }

  $: if (searchOptions.searchType === "String") {
    if (searchOptions.regex) {
      placeholderString = "Search for a Regex Pattern";
    } else {
      placeholderString = "Search for a String";
    }
  } else if (searchOptions.searchType === "Bytes") {
    searchOptions.regex = false; // Regex for bytes not yet implemented
    placeholderString = "Search for Bytes";
  }
</script>

<div class="searchbar">
  <select bind:value="{searchOptions.searchType}">
    {#each searchTypes as type}
      <option value="{type}">
        {type}
      </option>
    {/each}
  </select>
  <form
    on:submit|preventDefault="{async (e) => {
      if (searchQuery === undefined || searchQuery.length === 0) {
        searchResults.matches = undefined;
        prevQuery = '';
        prevOptions = {};
      } else if (isRepeatedQuery()) {
        nextMatch();
      } else {
        await doSearch();
      }
    }}"
    on:keyup|preventDefault="{async (e) => {
      if (e.keyCode === 13) {
        // Ignore enter (handled by on:submit)
        return;
      }
      if (
        !liveUpdate ||
        searchQuery === undefined ||
        searchQuery.length === 0
      ) {
        searchResults.matches = undefined;
        prevQuery = '';
        prevOptions = {};
      } else {
        await doSearch();
      }
    }}"
  >
    <label>
      <input placeholder="{placeholderString}" bind:value="{searchQuery}" />
    </label>
  </form>
  {#if searchOptions.searchType == "String"}
    <div class="optionbar">
      <Checkbox
        checked="{false}"
        bind:value="{searchOptions.regex}"
        leftbox="{true}"
      >
        Pattern
      </Checkbox>
      <Checkbox
        checked="{false}"
        bind:value="{searchOptions.caseIgnore}"
        leftbox="{true}"
      >
        Ignore Case
      </Checkbox>
    </div>
  {/if}
  {#if showResultsWidgets && searchResults.matches}
    <div class="resultwidgets">
      {#if searchResults.matches.length > 0}<p class="resultcount">
          {searchResults.index + 1}/{searchResults.matches.length}
        </p>
        <button on:click="{nextMatch}">&#8595;</button>
        <button on:click="{prevMatch}">&#8593;</button>
      {:else}
        <p class="resultcount">No match</p>
      {/if}
    </div>
  {/if}
</div>
