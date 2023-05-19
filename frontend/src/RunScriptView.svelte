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
  import FileBrowser from "./FileBrowser.svelte";
  import hljs from "highlight.js";
  import python from "highlight.js/lib/languages/python";
  import { selected, selectedResource } from "./stores";

  hljs.registerLanguage("python", python);

  export let modifierView, resourceNodeDataMap;
  let files = null,
    loaded_script = [],
    errorMessage;

  $: if (files) {
    files[0].text().then((value) => {
      loaded_script = value.split("\n");
    });
  }

  async function runLoadedScript() {
    try {
      const results = await $selectedResource.run_component(
        "RunScriptModifier",
        "ofrak.core.generic_script.UserScript",
        {
          kwargs: [],
          args: [],
          function_name: "main",
          code: loaded_script.join("\n"),
        }
      );
      resourceNodeDataMap[$selected] = {
        collapsed: false,
        childrenPromise: $selectedResource.get_children(),
      };
      for (const result in results) {
        if (result === "modified") {
          for (const resource of results[result]) {
            resourceNodeDataMap[resource["id"]] = {
              modified: true,
            };
          }
        }
      }
      const orig_selected = $selected;
      $selected = undefined;
      $selected = orig_selected;
      modifierView = undefined;
    } catch (err) {
      try {
        const parsed = JSON.parse(err.message);
        errorMessage = `${parsed.type}: ${parsed.message}`;
      } catch (_) {
        errorMessage = `Error: ${err.message}`;
      }
    }
  }
</script>

<link rel="stylesheet" href="./code.css" />

<div class="container">
  <div class="inputs">
    <FileBrowser multiple="{false}" bind:files="{files}" />
  </div>
  <div class="hbox">
    <div class="line-numbers">
      {#each loaded_script as _, index}
        <div>{index + 1}</div>
      {/each}
    </div>

    <span class="spacer"></span>

    <div class="textarea">
      <code>
        {@html hljs.highlight(loaded_script.join("\n"), {
          language: "python",
        }).value}
      </code>
    </div>
    {#if errorMessage}
      <p class="error">
        Error:
        {errorMessage}
      </p>
    {/if}
  </div>
  <div class="actions">
    <button on:click="{runLoadedScript}"> Run script </button>
    <button on:click="{() => (modifierView = undefined)}">Cancel</button>
  </div>
</div>
