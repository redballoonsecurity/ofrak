<style>
  label {
    margin-right: 1em;
    display: inline-flex;
    flex-direction: row;
    flex-wrap: nowrap;
    justify-content: flex-start;
    align-items: center;
    align-content: stretch;
    white-space: nowrap;
    user-select: none;
    cursor: pointer;
  }

  label input[type="checkbox"] {
    display: none;
  }

  label input[type="checkbox"] + span {
    width: 1em;
    height: 1em;
    background: var(--main-bg-color);
    color: var(--main-fg-color);
    border: 1px solid var(--main-fg-color);
    margin-left: 1ch;
    box-sizing: content-box;
  }

  label input[type="checkbox"].leftbox + span {
    margin-left: 0;
    margin-right: 1ch;
  }

  label input[type="checkbox"]:checked + span::after {
    content: "";
    display: block;
    position: relative;
    margin: 0.25em;
    width: 0.5em;
    height: 0.5em;
    color: var(--main-fg-color);
    background: var(--main-fg-color);
    border: none;
  }

  label input[type="checkbox"].leftbox + span {
    margin-left: 0;
    margin-right: 1ch;
  }

  .nomargin {
    margin: 0;
  }
</style>

<script>
  export let checked,
    value,
    leftbox = false,
    nomargin = false;

  $: value = checked;
</script>

<label class:nomargin="{nomargin}">
  {#if leftbox}
    <input class:leftbox="{leftbox}" type="checkbox" bind:checked="{checked}" />
    <span></span>
  {/if}
  <slot />
  {#if !leftbox}
    <input type="checkbox" bind:checked="{checked}" />
    <span></span>
  {/if}
</label>
