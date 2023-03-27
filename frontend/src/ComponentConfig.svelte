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
  form {
    background: inherit;
    color: inherit;
    border: none;
    border-bottom: 1px solid white;
    flex-grow: 1em;
    margin-left: 2em;
    border: 2px solid rgb(255, 255, 255) (255, 255, 255);
    border-radius: 4px;
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
  import { selectedResource } from "./stores";
  import { onMount } from "svelte";
  import ComponentConfigField from "./ComponentConfigField.svelte";
  import LoadingText from "./LoadingText.svelte";

  export let modifierView, selectedComponent, resourceNodeDataMap;
  let errorMessage,
    ofrakConfigsPromise = new Promise(() => {});
  let field_entries = {};

  function refreshResource() {
    // Force hex view refresh with colors
    const originalSelected = $selectedResource;
    $selectedResource = undefined;
    $selectedResource = originalSelected;
  }

  onMount(async () => {
    try {
      ofrakConfigsPromise =
        $selectedResource.get_config_for_component(selectedComponent);
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
  <p>Configure component to be run.</p>
  {#await ofrakConfigsPromise}
    <LoadingText />
  {:then ofrakConfig}
    {#if ofrakConfig.length != 0}
      {ofrakConfig["name"]};
      {#each ofrakConfig["fields"] as field}
        <ComponentConfigField
          field="{field}"
          field_name="{field['name']}"
          field_type="{field['type']}"
          bind:field_entries="{field_entries}"
        />
      {/each}
    {:else}
      <!-- TODO: How run component when no config is required? -->
      {$selectedResource.run_component(
        selectedComponent,
        null,
        field_entries
      )}
    {/if}

    <button
      on:click="{(e) => {
        $selectedResource.run_component(
          selectedComponent,
          "None",
          field_entries
        );
        resourceNodeDataMap[$selectedResource] = {
            collapsed: false,
            childrenPromise: $selectedResource.get_children(),
          };
        refreshResource();
        modifierView = undefined;
      }}"
    >
      Run Component
    </button>
  {:catch}
    <p>Failed to get config for OFRAK component!</p>
    <p>The back end server may be down.</p>
  {/await}
  {#if errorMessage}
    <p class="error">
      Error:
      {errorMessage}
    </p>
  {/if}
  <button on:click="{() => (modifierView = undefined)}">Cancel</button>
</div>
