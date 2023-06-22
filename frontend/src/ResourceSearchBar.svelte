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
          goNextMatch = () => {},
          goPrevMatch = () => {};
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
      await search(searchQuery, searchType);
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
    <button on:click={goNextMatch}>↓</button>
    <button on:click={goPrevMatch}>↑</button>
  </div>
</div>
