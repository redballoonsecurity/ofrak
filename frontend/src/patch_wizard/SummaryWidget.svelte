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
  }

  .invalid {
    opacity: 60%;
  }
</style>

<script>
  import Button from "../utils/Button.svelte";

  export let title, markError, valid, updateFunction;

  let collapsed = false;
</script>

<div class="{valid ? 'body' : 'body invalid'}">
  <div class="header-bar">
    <button on:click="{() => (collapsed = !collapsed)}">
      {#if collapsed}
        [+]
      {:else}
        [-]
      {/if}
    </button>
    {title}

    {#if !valid}
      <Button style="opacity: 100%" on:click="{updateFunction}">Update</Button>
    {/if}

    {#if markError}
      <p class="error-mark">[ ! ]</p>
    {/if}
  </div>
  {#if !collapsed}
    <div class="slot">
      <slot />
    </div>
  {/if}
</div>
