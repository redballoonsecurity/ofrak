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
    width: 100%;
    flex-grow: 1;
    height: 2em;
  }
</style>

<script>
  import { selectedResource } from "./stores";

  let searchType, searchQuery;
  let searchTypes = ["String", "Bytes"];
  let searchFilter = null;

  export let search,
          searchResults;

  searchResults.matches = undefined;
  searchResults.index = 0;

  let prevQuery = '';

  function nextMatch(){
    let nextIndex = searchResults.index + 1;
      if (nextIndex >= searchResults.matches.length){
        nextIndex = 0;
      }
      searchResults = {matches: searchResults.matches, index: nextIndex}
  }

  function prevMatch(){
    let nextIndex = searchResults.index - 1;
      if (nextIndex < 0){
        nextIndex = Math.max(searchResults.matches.length - 1, 0)
      }
      searchResults = {matches: searchResults.matches, index: nextIndex}
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
      if (searchQuery.length === 0){
        searchResults.matches = undefined;
        prevQuery = '';
      } else if (searchQuery == prevQuery){
        nextMatch();
      } else {
        searchResults.matches = await search(searchQuery, searchType);
        searchResults.index = 0;
        prevQuery = searchQuery;
      }
    }}"
  >
    <label>
      <input
        placeholder=" Search for a {searchType}"
        bind:value="{searchQuery}"
      />
    </label>
  </form>
  <div>
    {#if (searchResults.matches !== undefined && searchResults.matches !== null)}
      {#if searchResults.matches.length > 0}
        {searchResults.index + 1}/{searchResults.matches.length}
      {:else}
        No match
      {/if}
    {/if}
    <button on:click={nextMatch}>↓</button>
    <button on:click={prevMatch}>↑</button>
  </div>
</div>
