<style>
  .box {
    border: thin solid;
    margin: 0.5em 0.5em 1em;
  }
  .header {
    display: inline-flex;
    height: 2em;
    border: thin solid;
    width: 100%;
    align-items: center;
  }

  .header-title {
    margin-left: 1em;
  }

  button {
    border-style: none;
  }

  .options-toggle {
    margin-left: auto;
    margin-right: 0.5em;
  }

  .optional-button {
    height: 100%;
    padding-left: 1ch;
  }

  .script-box {
    padding-left: 0.5em;
    overflow-x: scroll;
  }

  .edit-name-input {
    width: 100%;
    background-color: var(--main-bg-color);
    color: var(--main-fg-color);
    margin-right: 1em;
  }
</style>

<script>
  import Script from "../utils/Script.svelte";
  import Icon from "../utils/Icon.svelte";
  import Button from "../utils/Button.svelte";

  export let sourceInfo, parentDeleteSource, onChangeCallback;
  let sourceHidden = true;
  let showOptions = false;

  let useCFormatting = ["c", "h"].includes(sourceInfo.name.split(".").at(-1));

  async function downloadSource() {
    const lines = sourceInfo.body.join("\n");
    if (lines.length === 0) {
      return;
    }
    const blob = new Blob([lines], { type: "application/x-python-code" });
    const blobUrl = URL.createObjectURL(blob);
    const a = document.createElement("a");
    a.href = blobUrl;
    a.target = "_blank";
    a.download = sourceInfo.name;
    a.click();
    URL.revokeObjectURL(blobUrl);
  }

  async function replaceSource() {
    let input = document.createElement("input");
    input.type = "file";
    input.onchange = async (_) => {
      const file = Array.from(input.files).pop();
      // TODO: Send file to backend in here
      file.text().then((t) => (sourceInfo.body = t.split("\n")));
    };
    input.click();
    onChangeCallback();
  }

  async function deleteSource() {
    await parentDeleteSource(sourceInfo);
  }
</script>

<div class="box">
  <div class="header">
    <button on:click="{() => (sourceHidden = !sourceHidden)}">
      {#if sourceHidden}
        [+]
      {:else}
        [-]
      {/if}
    </button>
    {#if showOptions}
      <label class="edit-name-input">
        <input
          class="edit-name-input"
          placeholder="{sourceInfo.name}"
          bind:value="{sourceInfo.name}"
          on:focusout="{onChangeCallback}"
        />
      </label>
      <button
        class="optional-button"
        title="Download file"
        on:click="{downloadSource}"
      >
        <Icon url="/icons/download.svg" />
      </button>
      <button
        class="optional-button"
        title="Upload new version"
        on:click="{replaceSource}"
      >
        <Icon url="/icons/upload.svg" />
      </button>
      <button class="optional-button" title="Delete" on:click="{deleteSource}">
        <Icon url="/icons/trash.svg" />
      </button>
      <button
        class="options-toggle"
        on:click="{() => (showOptions = !showOptions)}"
        ><Icon url="/icons/error.svg" /></button
      >
    {:else}
      <p class="header-title">{sourceInfo.name}</p>
      <button
        class="options-toggle"
        on:click="{() => (showOptions = !showOptions)}">...</button
      >
    {/if}
  </div>

  {#if !sourceHidden}
    <div class="script-box">
      <Script
        language="{useCFormatting ? 'c' : ''}"
        script="{sourceInfo.body}"
      />
    </div>
  {/if}
</div>
