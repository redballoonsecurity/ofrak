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

  .nowrap {
    white-space: nowrap;
  }

  .error {
    margin-top: 2em;
  }
</style>

<script>
  import { calculator } from "../helpers.js";
  import {
    selected,
    selectedResource,
    resourceNodeDataMap,
  } from "../stores.js";
  import Button from "../utils/Button.svelte";

  export let modifierView, dataLenPromise;
  let startInput, endInput, dataLength, errorMessage;

  $: dataLenPromise.then((r) => {
    dataLength = r;
  });

  function refreshResource() {
    // Force tree view children refresh
    $resourceNodeDataMap[$selected].collapsed = false;
    $resourceNodeDataMap[$selected].childrenPromise =
      $selectedResource.get_children();

    // Force hex view refresh with colors
    const originalSelected = $selected;
    $selected = undefined;
    $selected = originalSelected;
  }

  async function createChild() {
    try {
      let startOffset = calculator.calculate(startInput.value);
      let endOffset = calculator.calculate(endInput.value);
      if ($selectedResource) {
        await $selectedResource.create_child(undefined, undefined, undefined, [
          startOffset,
          endOffset,
        ]);
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
      Carve out a child resource from a range of the current resource's data.
    </p>
    <p>
      Hex input and basic arithmetic operations with grouping are supported. For
      example: <code class="nowrap"
        >0xbeefbeef + 0x10 * 5^((4 + 4 - 2) / 3)</code
      >.
    </p>
    <label>
      Starting offset:
      <input type="text" bind:this="{startInput}" value="{0}" />
    </label>
    <label>
      Ending offset:
      <input
        type="text"
        bind:this="{endInput}"
        value="{dataLength && !endInput.value
          ? `0x${dataLength.toString(16)}`
          : ''}"
      />
    </label>
    {#if errorMessage}
      <p class="error">
        Error:
        {errorMessage}
      </p>
    {/if}
  </div>
  <div class="actions">
    <Button on:click="{createChild}">Create Child</Button>
    <Button on:click="{() => (modifierView = undefined)}">Cancel</Button>
  </div>
</div>
