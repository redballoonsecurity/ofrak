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
  .optionbar {
    padding-bottom: 0;
    padding-top: 0;
  }
</style>

<script>
  import Checkbox from "./Checkbox.svelte";
  export let rootResource, searchFilter;
  let searchType, searchQuery, bytesInput, regex, ph_string;
  let searchTypes = ["String", "Bytes"];

  $: if (searchQuery != null && searchType == "Bytes") {
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
      ph_string = " Search for a Regex Pattern";
    } else {
      ph_string = " Search for a String";
    }
  } else if (searchType == "Bytes") {
    regex = false; // Regex for bytes not yet implemented
    ph_string = " Search for Bytes";
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
        searchFilter = await rootResource.search_for_string(searchQuery, regex);
      } else if (searchType == 'Bytes') {
        searchFilter = await rootResource.search_for_bytes(searchQuery, false);
      }
    }}"
  >
    <label>
      <input placeholder="{ph_string}" bind:value="{searchQuery}" />
    </label>
  </form>
</div>

<div class="optionbar">
  {#if searchType == "String"}
    <Checkbox checked="{false}" bind:value="{regex}" leftbox="{true}">
      Pattern
    </Checkbox>
  {/if}
</div>
