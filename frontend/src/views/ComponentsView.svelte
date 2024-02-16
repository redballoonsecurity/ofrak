<style>
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
    margin-top: 1em;
  }

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
  import {
    selected,
    selectedResource,
    resourceNodeDataMap,
  } from "../stores.js";
  import { splitAndCapitalize } from "../helpers.js";
  import { onMount } from "svelte";

  import SerializerInputForm from "../utils/SerializerInputForm.svelte";
  import LoadingText from "../utils/LoadingText.svelte";
  import Checkbox from "../utils/Checkbox.svelte";
  import Button from "../utils/Button.svelte";

  export let modifierView;
  let errorMessage,
    allComponents = true,
    includeAnalyzers = false,
    includeModifiers = false,
    includePackers = false,
    includeUnpackers = false,
    targetFilter = null,
    selectedComponent = null,
    ofrakComponentsPromise = new Promise(() => {}),
    ofrakTargetsPromise = new Promise(() => {}),
    ofrakConfigsPromise = new Promise(() => {}),
    config = {},
    ofrakConfigName = null;

  async function getTargetsAndComponents() {
    try {
      ofrakTargetsPromise = $selectedResource.get_tags_and_num_components(
        allComponents,
        includeAnalyzers,
        includeModifiers,
        includePackers,
        includeUnpackers
      );
      ofrakComponentsPromise = $selectedResource.get_components(
        allComponents,
        targetFilter,
        includeAnalyzers,
        includeModifiers,
        includePackers,
        includeUnpackers
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
      allComponents,
      includeAnalyzers,
      includeModifiers,
      includePackers,
      includeUnpackers,
      targetFilter
    );
  }

  $: if (selectedComponent) {
    try {
      ofrakConfigsPromise =
        $selectedResource.get_config_for_component(selectedComponent);
    } catch (err) {
      try {
        errorMessage = `Error: ${JSON.parse(err.message).message}`;
      } catch (_) {
        errorMessage = `Error: ${err.message}`;
      }
    }
  }

  $: runComponent = async () => {
    let ofrakConfig = await ofrakConfigsPromise;
    if (ofrakConfig.length != 0) {
      ofrakConfigName = ofrakConfig["name"];
    }
    try {
      const results = await $selectedResource.run_component(
        selectedComponent,
        ofrakConfig["type"],
        config
      );
      if (!$resourceNodeDataMap[$selected]) {
        $resourceNodeDataMap[$selected] = {};
      }
      $resourceNodeDataMap[$selected].collapsed = false;
      $resourceNodeDataMap[$selected].childrenPromise =
        $selectedResource.get_children();
      for (const result in results) {
        if (result === "modified") {
          for (const resource of results[result]) {
            if (!$resourceNodeDataMap[resource["id"]]) {
              $resourceNodeDataMap[resource["id"]] = {};
            }
            $resourceNodeDataMap[resource["id"]].lastModified = true;
          }
        }
      }
      const orig_selected = $selected;
      $selected = undefined;
      $selected = orig_selected;
      modifierView = undefined;
    } catch (err) {
      try {
        const parsed = JSON.parse(err.message);
        errorMessage = `${parsed.type}: ${parsed.message}`;
      } catch (_) {
        errorMessage = `Error: ${err.message}`;
      }
    }
  };

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
          <select bind:value="{targetFilter}">
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
        <Checkbox bind:checked="{includeAnalyzers}" leftbox="{true}">
          Include Analyzers
        </Checkbox>
        <Checkbox bind:checked="{includeModifiers}" leftbox="{true}">
          Include Modifiers
        </Checkbox>
        <Checkbox bind:checked="{includePackers}" leftbox="{true}">
          Include Packers
        </Checkbox>
        <Checkbox bind:checked="{includeUnpackers}" leftbox="{true}">
          Include Unpackers
        </Checkbox>
      </div>
      {#await ofrakComponentsPromise}
        <LoadingText />
      {:then ofrakComponents}
        <div class="checkboxes">
          <select bind:value="{selectedComponent}">
            <option value="{null}">Select a component to run</option>
            {#each ofrakComponents.sort() as ofrakComponent}
              <option value="{ofrakComponent}">
                {ofrakComponent}
              </option>
            {/each}
          </select>
          <Checkbox bind:checked="{allComponents}" leftbox="{true}">
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
        {#await ofrakConfigsPromise}
          <LoadingText />
        {:then ofrakConfig}
          {#if ofrakConfig.length != 0}
            <p>Configure {splitAndCapitalize(selectedComponent)}:</p>
            <SerializerInputForm node="{ofrakConfig}" bind:element="{config}" />
          {/if}
        {:catch}
          <p>Failed to get config for {selectedComponent}!</p>
          <p>The back end server may be down.</p>
        {/await}
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
    <Button on:click="{runComponent}">
      Run {selectedComponent}
    </Button>
    <Button on:click="{() => (modifierView = undefined)}">Cancel</Button>
  </div>
</div>
