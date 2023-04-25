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

  .label {
    padding-left: 10px;
  }

  .checkboxes {
    display: flex;
    flex-direction: column;
    flex-wrap: wrap;
    justify-content: space-evenly;
    align-items: flex-end;
    align-content: center;
    white-space: nowrap;
    float: left;
    direction: rtl;
  }

  .dropdown {
    float: right;
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
  import ComponentConfig from "./ComponentConfig.svelte";
  import LoadingText from "./LoadingText.svelte";
  import Checkbox from "./Checkbox.svelte";
  import AddTagView from "./AddTagView.svelte";

  export let modifierView, resourceNodeDataMap, dataPromise;
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

  async function getTargets() {
    try {
      ofrakTargetsPromise = $selectedResource.get_tags_and_num_components(
        only_targets,
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

  getTargets();

  async function getComponents() {
    try {
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

  onMount(async () => {
    selectedComponent = undefined;
    try {
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
  });
</script>

<div class="container">
  <div class="inputs">
    <p>Select component to run on resource.</p>
    {#await ofrakTargetsPromise}
      <LoadingText />
    {:then ofrakTags}
      <form class="dropdown" on:change|preventDefault="{getComponents}">
        Tag Filter: <select
          on:click|stopPropagation="{() => undefined}"
          bind:value="{target_filter}"
        >
          <option value="{null}">None</option>
          {#each ofrakTags as [ofrakTag, numComponents]}
            {#if numComponents != 0}
              <option value="{ofrakTag}">
                {ofrakTag} ({numComponents})
              </option>
            {/if}
          {/each}
        </select>
      </form>
    {:catch}
      <p>Failed to get the list of OFRAK components!</p>
      <p>The back end server may be down.</p>
    {/await}
    <form
      class="checkboxes "
      on:change|preventDefault="{getComponents}"
      on:change|preventDefault="{getTargets}"
    >
      <Checkbox bind:checked="{only_targets}"
        ><div class="label">Only Targetable Components</div></Checkbox
      >
      <Checkbox bind:checked="{incl_analyzers}"
        ><div class="label">Include Analyzers</div></Checkbox
      >
      <Checkbox bind:checked="{incl_modifiers}"
        ><div class="label">Include Modifiers</div></Checkbox
      >
      <Checkbox bind:checked="{incl_packers}"
        ><div class="label">Include Packers</div></Checkbox
      >
      <Checkbox bind:checked="{incl_unpackers}"
        ><div class="label">Include Unpackers</div></Checkbox
      >
    </form>
    {#await ofrakComponentsPromise}
      <LoadingText />
    {:then ofrakComponents}
      <form class="dropdown">
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
      {#if selectedComponent != null}
        <ComponentConfig selectedComponent="{selectedComponent}" modifierView="{modifierView}" resourceNodeDataMap="{resourceNodeDataMap}"/>
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
