<style>
  .buttonbar {
    position: sticky;
    top: 0;
    left: 0;
    display: flex;
    flex-direction: row;
    flex-wrap: nowrap;
    align-items: start;
    justify-content: end;
    overflow: auto;
  }
</style>

<script>
  import hljs from "highlight.js";
  import python from "highlight.js/lib/languages/python";
  import Button from "../utils/Button.svelte";
  import Script from "../utils/Script.svelte";
  import Icon from "../utils/Icon.svelte";

  import { script, selectedResource } from "../stores.js";
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
    --button-padding="0.5em 1em 0em 1em"
    --button-margin="0 0.5em 0 0.5em"
    --button-border="0"
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
    --button-padding="0.5em 1em 0em 1em"
    --button-margin="0 0.5em 0 0"
    --button-border="0"
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
  <Button
    --button-padding="0.5em 1em 0em 1em"
    --button-margin="0 0.5em 0 0"
    --button-border="0"
    on:click="{() => (bottomLeftPane = undefined)}"
  >
    <Icon url="/icons/error.svg" />
  </Button>
</div>
<Script script="{$script}" />
