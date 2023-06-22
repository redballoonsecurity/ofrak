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
  export let rootResource, searchFilter;
  let searchType, searchQuery, bytesInput;
  let searchTypes = ["String", "Bytes"];

  $: if (searchQuery != null && searchType == "Bytes") {
    searchQuery = searchQuery.match(/[0-9a-fA-F]{1,2}/g).join(" ");
    console.log(searchQuery);
    bytesInput?.setCustomValidity("");
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
      if (searchType == 'String') {
        searchFilter = await rootResource.search_for_string(searchQuery);
      } else if (searchType == 'Bytes') {
        searchFilter = await rootResource.search_for_bytes(searchQuery);
      }
    }}"
  >
    <label>
      {#if searchType == "String"}
        <input placeholder=" Search for a String" bind:value="{searchQuery}" />
      {:else if searchType == "Bytes"}
        <input
          placeholder=" Search for Bytes"
          pattern="([0-9a-fA-F][0-9a-fA-F]\s*)*"
          bind:value="{searchQuery}"
        />
      {/if}
    </label>
  </form>
</div>
