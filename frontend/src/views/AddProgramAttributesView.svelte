<style>
  form {
    justify-content: space-between;
    align-items: center;
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

  .row {
    justify-content: space-evenly;
    align-items: baseline;
    align-content: center;
    white-space: nowrap;
    margin-bottom: 1em;
  }
</style>

<script>
  import {
    selected,
    selectedResource,
    settings,
    resourceNodeDataMap,
  } from "../stores.js";
  import Button from "../utils/Button.svelte";
  import { onMount } from "svelte";
  import LoadingText from "../utils/LoadingText.svelte";
  import { cleanOfrakType } from "../helpers";

  export let modifierView;
  let errorMessage,
    ofrakProgramAttributesPromise = new Promise(() => {});
  let selected_attribute = {};

  async function refreshResource() {
    // Force tree view children refresh
    $resourceNodeDataMap[$selected].collapsed = false;
    $resourceNodeDataMap[$selected].childrenPromise =
      $selectedResource.get_children();

    // Force resource refresh by getting latest model from backend
    await $selectedResource.get_latest_model();

    // Force hex view refresh with colors
    const originalSelected = $selected;
    $selected = undefined;
    $selected = originalSelected;
  }

  async function addProgramAttributes() {
    if (
      selected_attribute.isa &&
      selected_attribute.bit_width &&
      selected_attribute.endianness
    ) {
      modifierView = undefined;
      let program_attributes = JSON.stringify([
        "ofrak.core.architecture.ProgramAttributes",
        {
          isa: selected_attribute.isa,
          sub_isa: selected_attribute.sub_isa,
          bit_width: selected_attribute.bit_width,
          endianness: selected_attribute.endianness,
          processor: selected_attribute.processor,
        },
      ]);
      await $selectedResource.add_program_attributes(program_attributes);
      await refreshResource();
    }
  }

  onMount(async () => {
    try {
      const r = await fetch(
        `${$settings.backendUrl}/get_all_program_attributes`
      );
      if (!r.ok) {
        throw Error(JSON.stringify(await r.json(), undefined, 2));
      }

      const ofrakProgramAttributes = await r.json();
      ofrakProgramAttributesPromise = ofrakProgramAttributes;
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
    <p>Select ProgramAttributes to add to resource.</p>
    {#await ofrakProgramAttributesPromise}
      <LoadingText />
    {:then ofrakProgramAttributes}
      {#if ofrakProgramAttributes && ofrakProgramAttributes.length > 0}
        <form
          on:submit="{(e) => {
            e.preventDefault();
            addProgramAttributes();
          }}"
        >
          {#each ofrakProgramAttributes as ofrakProgramAttributesType}
            <div class="row">
              {ofrakProgramAttributesType[0]}
              {#if ofrakProgramAttributesType[0] == "sub_isa" || ofrakProgramAttributesType[0] == "processor"}(optional){/if}:
              <select
                on:click="{(e) => {
                  e.stopPropagation();
                }}"
                bind:value="{selected_attribute[ofrakProgramAttributesType[0]]}"
              >
                <option value="{null}"
                  >Select {ofrakProgramAttributesType[0]}</option
                >
                {#each ofrakProgramAttributesType[1] as avail_option}
                  <option value="{avail_option}">
                    {cleanOfrakType(avail_option)}
                  </option>
                {/each}
              </select>
            </div>
          {/each}
          <div class="row">
            <Button
              --button-margin="0 .5em 0 .5em"
              --button-padding=".5em 1em .5em 1em"
              on:click="{(e) => {
                e.stopPropagation();
              }}"
              disabled="{!selected_attribute['isa'] ||
                !selected_attribute['bit_width'] ||
                !selected_attribute['endianness']}"
              type="submit">Add</Button
            >
          </div>
        </form>
      {:else}
        No ProgramAttributes found!
      {/if}
    {:catch}
      <p>Failed to get the list of OFRAK ProgramAttributes!</p>
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
    <Button on:click="{() => (modifierView = undefined)}">Cancel</Button>
  </div>
</div>
