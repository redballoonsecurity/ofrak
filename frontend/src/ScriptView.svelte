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

  .close {
    position: sticky;
    top: 0;
    right: 0;
  }

  .close button {
    position: absolute;
    right: 0;
    top: 0;
    display: flex;
    align-items: center;
    justify-content: center;
    padding: 0.5em;
    border: 0;
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

  import Icon from "./Icon.svelte";

  import { script, selectedResource } from "./stores.js";
  import { onMount } from "svelte";

  hljs.registerLanguage("python", python);

  export let scriptView;

  onMount(async () => {
    await $selectedResource.get_script();
  });
</script>

<link rel="stylesheet" href="./code.css" />

<div class="close">
  <button on:click="{() => (scriptView = undefined)}">
    <Icon url="/icons/error.svg" />
  </button>
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
