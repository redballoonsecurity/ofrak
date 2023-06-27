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
    text-indent: 0.5em;
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
  let searchType,
    searchQuery,
    bytesInput,
    regex,
    placeholderString,
    caseIgnore,
    errorMessage;
  let searchTypes = ["String", "Bytes"];

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
      placeholderString = "Search for a Regex Pattern";
    } else {
      placeholderString = "Search for a String";
    }
  } else if (searchType == "Bytes") {
    regex = false; // Regex for bytes not yet implemented
    placeholderString = "Search for Bytes";
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
      try {
        if (searchType == 'String') {
          searchFilter = await rootResource.search_for_string(
            searchQuery,
            regex,
            caseIgnore
          );
        } else if (searchType == 'Bytes') {
          searchFilter = await rootResource.search_for_bytes(
            searchQuery,
            false
          );
        }
      } catch (err) {
        try {
          errorMessage = JSON.parse(err.message).message;
        } catch (_) {
          errorMessage = err.message;
        }
        console.log('Search Failed!');
        console.log(errorMessage);
      }
    }}"
  >
    <label>
      <input placeholder="{placeholderString}" bind:value="{searchQuery}" />
    </label>
  </form>
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
