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
    display: flex;
    flex-direction: column;
    flex-wrap: nowrap;
    justify-content: flex-start;
    align-items: stretch;
  }

  .inputs > *:first-child {
    margin-top: 0;
  }

  .checkboxes {
    display: flex;
    flex-direction: column;
    flex-wrap: nowrap;
    justify-content: flex-start;
    align-items: flex-start;
    align-content: baseline;
  }

  .error {
    margin-top: 2em;
  }

  .actions {
    display: flex;
    flex-direction: row;
    flex-wrap: nowrap;
    justify-content: space-evenly;
    align-items: center;
    align-content: center;
  }

  button,
  select,
  option {
    background-color: var(--main-bg-color);
    color: inherit;
    border: 1px solid;
    border-color: inherit;
    border-radius: 0;
    padding: 0.5em 1em;
    margin-left: 0.5em;
    margin-right: 0.5em;
    font-size: inherit;
    font-family: var(--font);
    box-shadow: none;
  }

  select {
    width: 100%;
    margin: 0;
    margin-bottom: 1em;
  }

  option {
    font-family: monospace;
  }

  .filters {
    display: flex;
    flex-direction: row;
    flex-wrap: nowrap;
    justify-content: space-between;
    align-items: flex-start;
    align-content: center;
  }

  .filters > * {
    flex-grow: 1;
    margin: 0 1em;
  }

  .filters > *:first-child {
    margin-left: 0;
  }

  .filters > *:last-child {
    margin-right: 0;
  }

  hr {
    border: 1px dashed var(--main-fg-color);
    width: 100%;
    margin: 2em 0;
    padding: 0;
    box-sizing: border-box;
  }
</style>

<script>
  import { selectedResource } from "./stores.js";
  import { onMount } from "svelte";

  import ComponentConfig from "./ComponentConfig.svelte";
  import LoadingText from "./LoadingText.svelte";
  import Checkbox from "./Checkbox.svelte";

  export let modifierView, resourceNodeDataMap;
  let errorMessage,
    only_targets = true,
    incl_analyzers = false,
    incl_modifiers = false,
    incl_packers = false,
    incl_unpackers = false,
    target_filter = null,
    selectedComponent = null,
    ofrakComponentsPromise = new Promise(() => {}),
    ofrakTargetsPromise = new Promise(() => {});

  async function getTargetsAndComponents() {
    try {
      ofrakTargetsPromise = $selectedResource.get_tags_and_num_components(
        only_targets,
        incl_analyzers,
        incl_modifiers,
        incl_packers,
        incl_unpackers
      );
      ofrakComponentsPromise = $selectedResource.get_components(
        only_targets,
        target_filter,
        incl_analyzers,
        incl_modifiers,
        incl_packers,
        incl_unpackers
      );
    } catch (err) {
      try {
        errorMessage = JSON.parse(err.message).message;
      } catch (_) {
        errorMessage = err.message;
      }
    }
  }

  getTargetsAndComponents();

  $: {
    getTargetsAndComponents(
      only_targets,
      incl_analyzers,
      incl_modifiers,
      incl_packers,
      incl_unpackers,
      target_filter
    );
  }

  onMount(async () => {
    selectedComponent = undefined;
    getTargetsAndComponents();
  });
</script>

<div class="container">
  <div class="inputs">
    <div class="filters">
      <div class="checkboxes">
        {#await ofrakTargetsPromise}
          <LoadingText />
        {:then ofrakTags}
          <select bind:value="{target_filter}">
            <option value="{null}">Filter by Tag</option>
            {#each ofrakTags as [ofrakTag, numComponents]}
              {#if numComponents != 0}
                <option value="{ofrakTag}">
                  {ofrakTag} ({numComponents})
                </option>
              {/if}
            {/each}
          </select>
        {:catch}
          <p>Failed to get the list of OFRAK components!</p>
          <p>The back end server may be down.</p>
        {/await}
        <Checkbox bind:checked="{incl_analyzers}" leftbox="{true}">
          Include Analyzers
        </Checkbox>
        <Checkbox bind:checked="{incl_modifiers}" leftbox="{true}">
          Include Modifiers
        </Checkbox>
        <Checkbox bind:checked="{incl_packers}" leftbox="{true}">
          Include Packers
        </Checkbox>
        <Checkbox bind:checked="{incl_unpackers}" leftbox="{true}">
          Include Unpackers
        </Checkbox>
      </div>
      {#await ofrakComponentsPromise}
        <LoadingText />
      {:then ofrakComponents}
        <div class="checkboxes">
          <select bind:value="{selectedComponent}">
            <option value="{null}">Select a component to run</option>
            {#each ofrakComponents as ofrakComponent}
              <option value="{ofrakComponent}">
                {ofrakComponent}
              </option>
            {/each}
          </select>
          <Checkbox bind:checked="{only_targets}" leftbox="{true}">
            Show all components
          </Checkbox>
        </div>
      {:catch}
        <p>Failed to get the list of OFRAK components!</p>
        <p>The back end server may be down.</p>
      {/await}
    </div>

    <hr />

    {#await ofrakComponentsPromise}
      <LoadingText />
    {:then ofrakComponents}
      {#if selectedComponent != null}
        <ComponentConfig
          selectedComponent="{selectedComponent}"
          modifierView="{modifierView}"
          resourceNodeDataMap="{resourceNodeDataMap}"
        />
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

  <div class="actions">
    <!-- TODO -->
    <button on:click="{() => alert('Not yet implemented')}">Run</button>
    <button on:click="{() => (modifierView = undefined)}">Cancel</button>
  </div>
</div>
