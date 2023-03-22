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

  .xboxparent {
    position: relative;
    align-items: flex-start;
  }

  .xbox {
    position: absolute;
    top: 0%;
    right: 0%;
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
  import hljs from "highlight.js/lib/core";
  import python from "highlight.js/lib/languages/python";
  hljs.registerLanguage("python", python);
  hljs.configure({
    cssSelector: "code",
    // TODO: Unescaped HTML warning seems to be incorrect. If so and we can't prevent it from displaying by "correcting" the code, we can disable with this option.
    // ignoreUnescapedHTML: true
  });

  import Icon from "./Icon.svelte";
  import { script } from "./stores.js";
  import { afterUpdate } from "svelte";

  export let scriptView;
  $: if ($script) {
    hljs.highlightAll();
  }
</script>

<link rel="stylesheet" href="./code.css" />

<div class="xboxparent">
  <div class="xbox">
    <button on:click="{() => (scriptView = undefined)}">
      <Icon url="/icons/error.svg" />
    </button>
  </div>
</div>

<div class="hbox">
  <div class="line-numbers">
    {#each Object.entries($script) as [index, _]}
      {#if index !== "0"}
        <div>{index}</div>
      {/if}
    {/each}
  </div>

  <span class="spacer"></span>

  <div class="textarea">
    {#each $script as line}
      <div><code id="apicode" class="language-python">{line}</code></div>
    {/each}
  </div>
</div>
