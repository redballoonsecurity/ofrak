<style>
  form {
    display: flex;
    flex-direction: row;
    flex-wrap: nowrap;
    justify-content: space-between;
    align-items: center;
  }

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

  .error {
    margin-top: 2em;
  }

  button,
  select,
  option {
    background-color: var(--main-bg-color);
    color: inherit;
    border: 1px solid;
    border-color: inherit;
    border-radius: 0;
    padding-top: 0.5em;
    padding-bottom: 0.5em;
    padding-left: 1em;
    padding-right: 1em;
    margin-left: 0.5em;
    margin-right: 0.5em;
    font-size: inherit;
    font-family: var(--font);
    box-shadow: none;
  }

  select {
    flex-grow: 1;
    margin: 0 2ch;
  }

  option {
    font-family: monospace;
  }
</style>

<script>
  import { selectedResource } from "./stores.js";
  import { onMount } from "svelte";
  import LoadingText from "./LoadingText.svelte";

  export let modifierView, resourceNodeDataMap, dataPromise;
  let errorMessage,
    ofrakComponentsPromise = new Promise(() => {}),
    selectedComponent;

  function chooseComponent() {
    if (selectedComponent) {
      modifierView = undefined;
      $selectedResource.get_config_for_componenet();
    }
  }

  onMount(async () => {
    try {
      ofrakComponentsPromise =
        $selectedResource.get_all_components_for_resource();
    } catch (err) {
      try {
        errorMessage = JSON.parse(err.message).message;
      } catch (_) {
        errorMessage = err.message;
      }
    }
  });
</script>

<div class="container">
  <div class="inputs">
    <p>Select component to run on resource.</p>
    {#await ofrakComponentsPromise}
      <LoadingText />
    {:then ofrakComponents}
      {#if ofrakComponents && ofrakComponents.length > 0}
        <form on:submit|preventDefault="{chooseComponent}">
          Run Component: <select
            on:click|stopPropagation="{() => undefined}"
            bind:value="{selectedComponent}"
          >
            <option value="{null}">Select a component to run</option>
            {#each ofrakComponents as ofrakComponent}
              <option value="{ofrakComponent}">
                {ofrakComponent}
              </option>
            {/each}
          </select>

          <button
            on:click|stopPropagation="{() => undefined}"
            disabled="{!selectedComponent}"
            type="submit">Run</button
          >
        </form>
      {:else}
        No components found!
      {/if}
    {:catch}
      <p>Failed to get the list of OFRAK components!</p>
      <p>The back end server may be down.</p>
    {/await}
    {#if errorMessage}
      <p class="error">
        Error:
        {errorMessage}
      </p>
    {/if}
  </div>
  <button on:click="{() => (modifierView = undefined)}">Cancel</button>
</div>
