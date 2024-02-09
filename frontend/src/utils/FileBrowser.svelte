<style>
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
  import Button from "./Button.svelte";
  export let files,
    input,
    multiple = false;
  let dragging = false;
</script>

<div
  on:dragover="{(e) => {
    e.preventDefault();
    dragging = true;
  }}"
  on:dragleave="{(e) => {
    e.preventDefault();
    dragging = false;
  }}"
  on:drop="{(e) => {
    e.preventDefault();
    files = e.dataTransfer.files;
    dragging = false;
  }}"
>
  {#if !dragging}
    <label class="filelabel">
      <slot />
      {#if multiple}
        <input type="file" multiple bind:this="{input}" bind:files="{files}" />
      {:else}
        <input type="file" bind:this="{input}" bind:files="{files}" />
      {/if}
      <span>
        <Button on:click="{() => input.click()}">Browse...</Button>
        {#if files}
          {Array.from(files)
            .map((f) => f?.name)
            .join(", ")}
        {:else}
          No file selected.
        {/if}
      </span>
    </label>
  {:else}
    Drop the files to upload.
  {/if}
</div>
