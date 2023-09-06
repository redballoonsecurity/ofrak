<style>
  button {
    padding-top: 0.5em;
    padding-bottom: 0.5em;
    padding-left: 1em;
    padding-right: 1em;
  }

  button:hover,
  button:focus {
    outline: none;
    box-shadow: inset 1px 1px 0 var(--main-fg-color),
      inset -1px -1px 0 var(--main-fg-color);
  }

  button:active {
    box-shadow: inset 2px 2px 0 var(--main-fg-color),
      inset -2px -2px 0 var(--main-fg-color);
  }

  .buttonbar {
    position: sticky;
    top: 0;
    left: 0;
    display: flex;
    flex-direction: row;
    flex-wrap: nowrap;
    align-items: start;
    justify-content: end;
  }

  .buttonbar button {
    display: flex;
    align-items: center;
    justify-content: center;
    padding: 0.5em;
    margin-left: 0.5em;
    border: 0;
    background: var(--main-bg-color);
  }

  .hbox {
    display: flex;
    flex-direction: row;
    flex-wrap: nowrap;
    justify-content: flex-start;
    align-items: stretch;
    line-height: var(--line-height);
    font-size: 0.95em;
  }

  .spacer {
    width: 2em;
    min-width: 2em;
  }

  .line-numbers {
    text-align: right;
  }

  .textarea {
    white-space: pre;
  }
</style>

<script>
  import hljs from "highlight.js";
  import python from "highlight.js/lib/languages/python";
  import Button from "./utils/Button.svelte";

  import Icon from "./Icon.svelte";

  import { script, selectedResource } from "./stores.js";
  import { onMount } from "svelte";

  hljs.registerLanguage("python", python);

  export let bottomLeftPane;

  onMount(async () => {
    await $selectedResource.update_script();
  });
</script>

<link rel="stylesheet" href="./code.css" />

<div class="buttonbar">
  <Button
    on:click="{async (e) => {
      const lines = $script.join('\n');
      if (lines.length === 0) {
        return;
      }
      if (window.clipboardData && window.clipboardData.setData) {
        return window.clipboardData.setData('Text', lines);
      } else if (
        document.queryCommandSupported &&
        document.queryCommandSupported('copy')
      ) {
        var textarea = document.createElement('textarea');
        textarea.textContent = lines;
        // Prevent scrolling to bottom of page in MS Edge
        textarea.style.position = 'fixed';
        document.body.appendChild(textarea);
        textarea.select();
        try {
          // Security exception may be thrown by some browsers
          return document.execCommand('copy');
        } catch (ex) {
          console.warn('Copy to clipboard failed.', ex);
          return false;
        } finally {
          document.body.removeChild(textarea);
        }
      }
    }}"
  >
    <Icon url="/icons/content_copy.svg" />
  </Button>
  <Button
    on:click="{async (e) => {
      const lines = $script.join('\n');
      if (lines.length === 0) {
        return;
      }
      const blob = new Blob([lines], { type: 'application/x-python-code' });
      const blobUrl = URL.createObjectURL(blob);
      const a = document.createElement('a');
      a.href = blobUrl;
      a.target = '_blank';
      a.download = 'script.py';
      a.click();
      URL.revokeObjectURL(blobUrl);
    }}"
  >
    <Icon url="/icons/download.svg" />
  </Button>
  <Button on:click="{() => (bottomLeftPane = undefined)}">
    <Icon url="/icons/error.svg" />
  </Button>
</div>

<div class="hbox">
  <div class="line-numbers">
    {#each $script as _, index}
      <div>{index + 1}</div>
    {/each}
  </div>

  <span class="spacer"></span>

  <div class="textarea">
    <code>
      {@html hljs.highlight($script.join("\n"), { language: "python" }).value}
    </code>
  </div>
</div>
