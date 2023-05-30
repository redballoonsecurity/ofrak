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
  import Checkbox from "./Checkbox.svelte";
  import { selected, selectedResource } from "./stores.js";

  export let modifierView, resourceNodeDataMap;
  let toFind,
    toReplace,
    nullTerminated = true,
    allowOverflow = false,
    errorMessage;

  function refreshResource() {
    // Force hex view refresh with colors
    const originalSelected = $selected;
    $selected = undefined;
    $selected = originalSelected;
  }

  async function findAndReplace() {
    try {
      if ($selectedResource) {
        const results = await $selectedResource.find_and_replace(
          toFind,
          toReplace,
          nullTerminated,
          allowOverflow
        );

        for (const result in results) {
          if (result === "modified") {
            for (const resource of results[result]) {
              resourceNodeDataMap[resource["id"]] = {
                modified: true,
              };
            }
          }
        }
      }

      modifierView = undefined;
      refreshResource();
    } catch (err) {
      try {
        errorMessage = JSON.parse(err.message).message;
      } catch (_) {
        errorMessage = err.message;
      }
    }
  }
</script>

<div class="container">
  <div class="inputs">
    <p>
      Replace all instances of a string with another string. Replacements occur
      in the data of the currently selected resource.
    </p>
    <label>
      String to find:
      <input type="text" bind:value="{toFind}" />
    </label>
    <label>
      String to replace:
      <input type="text" bind:value="{toReplace}" />
    </label>
    <div class="row">
      <Checkbox bind:checked="{nullTerminated}">
        Null terminate replacement string
      </Checkbox>
      <Checkbox bind:checked="{allowOverflow}">
        Allow overflowing replaced string
      </Checkbox>
    </div>
    {#if errorMessage}
      <p class="error">
        Error:
        {errorMessage}
      </p>
    {/if}
  </div>
  <div class="actions">
    <button on:click="{findAndReplace}">Find and Replace</button>
    <button on:click="{() => (modifierView = undefined)}">Cancel</button>
  </div>
</div>
