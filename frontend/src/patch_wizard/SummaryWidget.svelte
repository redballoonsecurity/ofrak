<style>
  button {
    border: none;
    margin-block-start: 1ch;
    margin-block-end: 1ch;
  }

  .body {
    border: thin solid;
  }

  .header-bar {
    border: thin solid;
    border-right: none;
    display: inline-flex;
    align-items: center;
    width: 100%;
  }

  .slot {
    padding: 1em;
  }

  .error-mark {
    color: red;
    font-weight: bold;
    margin-left: auto;
    margin-right: 1em;
    user-select: none;
  }

  .invalid {
    opacity: 60%;
  }

  .updateButton {
    margin-left: 2em;
  }
</style>

<script>
  import Button from "../utils/Button.svelte";

  export let title, markError, valid, updateFunction, errorReason;

  let collapsed = false;

  let updatePromise = Promise.resolve();

  let _valid = valid;

  $: if (valid === null) {
    // Null means this widget is always valid
    _valid = true;
  } else {
    _valid = valid;
  }
</script>

<div class="body">
  <div class="header-bar">
    <button on:click="{() => (collapsed = !collapsed)}">
      {#if collapsed}
        [+]
      {:else}
        [-]
      {/if}
    </button>
    {title}

    {#if valid !== null}
      <span class="updateButton" class:invalid="{_valid}">
        {#await updatePromise}
          <Button on:click="{() => {}}">Updating...</Button>
        {:then e}
          <Button
            on:click="{() => {
              updatePromise = updateFunction();
            }}"
          >
            {#if !_valid}
              ⮕Update⬅
            {:else}
              Update
            {/if}
          </Button>
        {:catch err}
          <Button
            on:click="{() => {
              updatePromise = updateFunction();
            }}"
          >
            {#if !_valid}
              ⮕Update⬅
            {:else}
              Update
            {/if}
          </Button>
        {/await}
      </span>
    {/if}

    {#if markError}
      <p class="error-mark" title="{errorReason}">[ ! ]</p>
    {/if}
  </div>
  {#if !collapsed}
    <div class="slot" class:invalid="{!_valid}">
      <slot />
    </div>
  {/if}
</div>
