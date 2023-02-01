<style>
  button {
    padding-top: 0.5em;
    padding-bottom: 0.5em;
    padding-left: 1em;
    padding-right: 1em;
    margin-right: 2ch;
  }

  button:hover,
  button:focus {
    outline: none;
    box-shadow: inset 1px 1px 0 currentColor, inset -1px -1px 0 currentColor;
  }

  button:active {
    box-shadow: inset 2px 2px 0 currentColor, inset -2px -2px 0 currentColor;
  }

  .filelabel {
    cursor: pointer;
    font-family: inherit;
    font-size: inherit;
    color: inherit;
    background: inherit;
    border-color: inherit;
    box-shadow: none;
    user-select: none;
    line-height: inherit;
  }

  .filelabel span {
    width: 100%;
    margin-left: 2ch;
    background: inherit;
    color: inherit;
    /* border-bottom: 1px solid var(--main-fg-color); */
  }

  input[type="file"] {
    display: none;
  }

  label {
    display: flex;
    flex-direction: row;
    flex-wrap: nowrap;
    justify-content: space-evenly;
    align-items: baseline;
    align-content: center;
    white-space: nowrap;
  }
</style>

<script>
  export let files, input;
</script>

<label class="filelabel">
  <slot />
  <input type="file" bind:this="{input}" bind:files="{files}" />
  <span>
    <button on:click="{() => input.click()}"> Browse... </button>
    {#if files}
      {Array.from(files)
        .map((f) => f?.name)
        .join(", ")}
    {:else}
      No file selected.
    {/if}
  </span>
</label>
