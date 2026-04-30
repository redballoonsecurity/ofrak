<style>
  form {
    display: flex;
    flex-direction: column;
    gap: 1em;
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
    margin-top: 1em;
    display: flex;
    flex-direction: row;
    flex-wrap: nowrap;
    justify-content: space-evenly;
    align-items: center;
    align-content: center;
  }

  .error {
    color: var(--error-color, #ff6b6b);
    margin-top: 1em;
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

  textarea {
    background-color: var(--main-bg-color);
    color: inherit;
    border: 1px solid;
    border-color: inherit;
    border-radius: 0;
    padding: 1em;
    font-size: 12px;
    font-family: monospace;
    line-height: 1.5;
    resize: vertical;
    min-height: 200px;
    width: 100%;
    box-sizing: border-box;
  }

  .form-group {
    display: flex;
    flex-direction: column;
    gap: 0.5em;
  }

  label {
    font-weight: bold;
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
  let errorMessage = "";
  let attributeTypesPromise = new Promise(() => {});
  let selectedAttributeType = null;
  let jsonPayload = "";

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

  function validateJSON() {
    try {
      JSON.parse(jsonPayload);
      return true;
    } catch (e) {
      errorMessage = `Invalid JSON: ${e.message}`;
      return false;
    }
  }

  async function submitAttributes() {
    if (!selectedAttributeType) {
      errorMessage = "Please select an attribute type";
      return;
    }

    if (!validateJSON()) {
      return;
    }

    try {
      errorMessage = "";
      const payload = JSON.parse(jsonPayload);

      const response = await fetch(
        `${$settings.backendUrl}/${$selectedResource.resource_id}/add_attributes`,
        {
          method: "POST",
          headers: { "Content-Type": "application/json" },
          body: JSON.stringify({
            type: selectedAttributeType.type,
            attributes: payload,
          }),
        }
      );

      if (!response.ok) {
        const error = await response.json();
        throw new Error(error.error || `HTTP ${response.status}`);
      }

      modifierView = undefined;
      await refreshResource();
    } catch (err) {
      errorMessage = err instanceof Error ? err.message : "Unknown error";
    }
  }

  function onAttributeTypeChange(e) {
    // Clear payload when type changes - user should provide JSON
    jsonPayload = "";
  }

  onMount(async () => {
    try {
      const response = await fetch(
        `${$settings.backendUrl}/get_all_resource_attributes`
      );
      if (!response.ok) {
        throw Error("Failed to fetch attribute types");
      }
      const types = await response.json();
      types.sort((a, b) =>
        cleanOfrakType(a.type).localeCompare(cleanOfrakType(b.type))
      );
      attributeTypesPromise = Promise.resolve(types);
    } catch (err) {
      errorMessage = err instanceof Error ? err.message : "Unknown error";
      attributeTypesPromise = Promise.resolve([]);
    }
  });
</script>

<div class="container">
  <div class="inputs">
    <p>Select a resource attribute type to add.</p>
    {#await attributeTypesPromise}
      <LoadingText />
    {:then attributeTypes}
      {#if attributeTypes && attributeTypes.length > 0}
        <form on:submit|preventDefault="{submitAttributes}">
          <div class="form-group">
            <label for="attr-type">Attribute Type:</label>
            <select
              id="attr-type"
              bind:value="{selectedAttributeType}"
              on:change="{onAttributeTypeChange}"
              on:click="{(e) => e.stopPropagation()}"
            >
              <option value="{null}">Select an attribute type</option>
              {#each attributeTypes as attrType}
                <option value="{attrType}">
                  {cleanOfrakType(attrType.type)}
                </option>
              {/each}
            </select>
          </div>

          {#if selectedAttributeType}
            <div class="form-group">
              <label for="json-payload">Configuration (JSON):</label>
              <textarea
                id="json-payload"
                bind:value="{jsonPayload}"
                placeholder="Edit JSON configuration here..."
                on:click="{(e) => e.stopPropagation()}"></textarea>
              <p style="font-size: 0.9em; color: #888; margin-top: 0.5em;">
                For nested objects, use format: <code
                  style="background: #f0f0f0; padding: 2px 4px;"
                  >["package.module.ClassName", {"{"}fields{"}"}]</code
                >
              </p>
            </div>
          {/if}

          <div class="actions">
            <Button
              --button-margin="0 .5em 0 .5em"
              --button-padding=".5em 1em .5em 1em"
              on:click="{(e) => {
                e.stopPropagation();
                modifierView = undefined;
              }}"
            >
              Cancel
            </Button>
            <Button
              --button-margin="0 .5em 0 .5em"
              --button-padding=".5em 1em .5em 1em"
              on:click="{(e) => e.stopPropagation()}"
              disabled="{!selectedAttributeType || !jsonPayload.trim()}"
              type="submit"
            >
              Add Attributes
            </Button>
          </div>
        </form>
      {:else}
        <p>No attribute types found!</p>
      {/if}
    {:catch err}
      <p>Failed to load attribute types!</p>
      <p>The back end server may be down.</p>
    {/await}
  </div>

  {#if errorMessage}
    <div class="error">{errorMessage}</div>
  {/if}
</div>
