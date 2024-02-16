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
  let comment, startInput, endInput, dataLength, errorMessage;

  $: dataLenPromise.then((r) => {
    dataLength = r;
  });

  function refreshResource() {
    $resourceNodeDataMap[$selected].commentsPromise =
      $selectedResource.get_comments();

    // Force hex view refresh with colors
    const originalSelected = $selected;
    $selected = undefined;
    $selected = originalSelected;
  }

  async function addComment() {
    try {
      let optional_range = null;
      if (dataLength) {
        let startOffset = startInput.value ? startInput.value : "0";
        let endOffset = endInput.value ? endInput.value : dataLength.toString();
        startOffset = calculator.calculate(startOffset);
        endOffset = calculator.calculate(endOffset);
        optional_range = [startOffset, endOffset];
      }
      if ($selectedResource) {
        await $selectedResource.add_comment(optional_range, comment.value);
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
    <p>Add a comment to this resource.</p>
    <label>
      Comment:
      <input type="text" bind:this="{comment}" />
    </label>
    {#if dataLength}
      <label>
        Starting offset (optional):
        <input type="text" bind:this="{startInput}" value="" />
      </label>
      <label>
        Ending offset (optional):
        <input type="text" bind:this="{endInput}" value="" />
      </label>
    {/if}
    {#if errorMessage}
      <p class="error">
        Error:
        {errorMessage}
      </p>
    {/if}
  </div>
  <div class="actions">
    <Button on:click="{addComment}">Add comment</Button>
    <Button on:click="{() => (modifierView = undefined)}">Cancel</Button>
  </div>
</div>
