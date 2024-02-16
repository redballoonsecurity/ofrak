<style>
  textarea {
    font-family: inherit;
    font-size: inherit;
    color: inherit;
    background: inherit;
    border: 1px solid;
    border-color: inherit;
    box-shadow: none;
    line-height: inherit;
    resize: none;
    flex-grow: 1;
    padding: 1em 1.5em;
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

  .nowrap {
    white-space: nowrap;
  }

  .error {
    margin-top: 2em;
  }
</style>

<script>
  import {
    buf2hex,
    chunkList,
    calculator,
    hexToByteArray,
  } from "../helpers.js";
  import {
    selected,
    resourceNodeDataMap,
    selectedResource as _selectedResource,
  } from "../stores.js";
  import Button from "../utils/Button.svelte";
  const selectedResource = $_selectedResource;

  export let modifierView, dataLenPromise;
  let startInput,
    endInput,
    startOffset,
    endOffset,
    dataLength,
    errorMessage,
    userData;

  $: dataLenPromise.then((r) => {
    dataLength = r;
  });

  function refreshResource() {
    // Force hex view refresh with colors
    const originalSelected = $selected;
    $selected = undefined;
    $selected = originalSelected;
  }

  async function getRange() {
    try {
      startOffset = calculator.calculate(startInput.value);
      endOffset = calculator.calculate(endInput.value);

      if (endOffset - startOffset > 0x100000) {
        if (
          !window.confirm(
            "Loading and editing a large range may be slow. Are you sure?"
          )
        ) {
          return;
        }
      }

      if (selectedResource) {
        let data = await selectedResource.get_data([startOffset, endOffset]);
        userData = chunkList(new Uint8Array(data), 16)
          .map((r) => buf2hex(r, " "))
          .join("\n");
      }
    } catch (err) {
      try {
        errorMessage = JSON.parse(err.message).message;
      } catch (_) {
        errorMessage = err.message;
      }
    }
  }

  async function modifyData() {
    try {
      const patchData = hexToByteArray(userData.replace(/\s/g, ""));

      const expectedPatchSize = endOffset - startOffset;
      if (
        patchData.length > expectedPatchSize &&
        !window.confirm(
          `Your patch overflows the original range by ${
            patchData.length - expectedPatchSize
          } bytes. Are you sure you want to proceed?`
        )
      ) {
        return;
      } else if (
        patchData.length < expectedPatchSize &&
        !window.confirm(
          `Your patch is smaller than the original range by ${
            expectedPatchSize - patchData.length
          } bytes. Are you sure you want to proceed?`
        )
      ) {
        return;
      }

      if (selectedResource) {
        await selectedResource.queue_patch(patchData, startOffset, endOffset);
      }
      if (!$resourceNodeDataMap[$selected]) {
        $resourceNodeDataMap[$selected] = {};
      }
      $resourceNodeDataMap[$selected].lastModified = true;
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
  {#if userData !== undefined && userData !== null}
    <p>
      Editing range 0x{startOffset.toString(16)} - 0x{endOffset.toString(16)}.
    </p>
    <p>
      Feel free to disregard whitespace when editing. "deadbeef" and "de ad be
      eef" and "dea d eef" are all evaluated the same.
    </p>
    <textarea
      autocomplete="off"
      autocorrect="off"
      spellcheck="false"
      wrap="off"
      bind:value="{userData}"></textarea>
    {#if errorMessage}
      <p class="error">
        Error:
        {errorMessage}
      </p>
    {/if}
    <div class="actions">
      <Button on:click="{modifyData}">Apply Edits</Button>
      <Button on:click="{() => (modifierView = undefined)}">Cancel</Button>
    </div>
  {:else}
    <div class="inputs">
      <p>Select a range of binary data to edit.</p>
      <p>
        Hex input and basic arithmetic operations with grouping are supported.
        For example: <code class="nowrap"
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
      <Button on:click="{getRange}">Edit Range</Button>
      <Button on:click="{() => (modifierView = undefined)}">Cancel</Button>
    </div>
  {/if}
</div>
