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

  .inputs > *:nth-child(1) {
    margin: 0 0 1em -1em;
  }

  .hbox {
    display: flex;
    flex-direction: row;
    flex-wrap: nowrap;
    justify-content: flex-start;
    align-items: stretch;
    line-height: var(--line-height);
    font-size: 0.95em;
    height: 16em;
    width: 100%;
    overflow: auto;
    flex-grow: 1;
    margin: 1em 0;
  }

  .container {
    display: flex;
    flex-direction: column;
    flex-wrap: nowrap;
    justify-content: flex-start;
    align-items: flex-start;
    min-height: 100%;
  }

  .actions {
    display: flex;
    flex-direction: row;
    flex-wrap: nowrap;
    justify-content: space-evenly;
    align-items: flex-start;
    align-content: flex-start;
    width: 100%;
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
  import LoadingText from "./LoadingText.svelte";
  import ComponentConfigNode from "./ComponentConfigNode.svelte";
  import Icon from "./Icon.svelte";

  import hljs from "highlight.js";
  import python from "highlight.js/lib/languages/python";

  import { selected, selectedResource } from "./stores";
  import { onMount } from "svelte";

  hljs.registerLanguage("python", python);

  export let modifierView, resourceNodeDataMap;
  let runScriptPromise,
    files = null,
    loadedScript = [],
    errorMessage,
    ofrakConfigsPromise = new Promise(() => {}),
    scriptParams = {};

  $: if (files) {
    files[0].text().then((value) => {
      loadedScript = value.split("\n");
    });
  }

  async function runLoadedScript() {
    try {
      const results = await $selectedResource.run_component(
        "RunScriptModifier",
        "ofrak.core.generic_script.RunScriptModifierConfig",
        Object.assign({ code: loadedScript.join("\n") }, scriptParams)
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
      throw err;
    }
  }

  onMount(async () => {
    try {
      ofrakConfigsPromise =
        $selectedResource.get_config_for_component("RunScriptModifier");
    } catch (err) {
      try {
        errorMessage = `Error: ${JSON.parse(err.message).message}`;
      } catch (_) {
        errorMessage = `Error: ${err.message}`;
      }
    }
  });
</script>

<link rel="stylesheet" href="./code.css" />

<div class="container">
  <div class="inputs">
    <div>
      <FileBrowser multiple="{false}" bind:files="{files}" />
    </div>
    {#await ofrakConfigsPromise}
      <LoadingText />
    {:then ofrakConfig}
      {#if ofrakConfig.length != 0}
        {#each ofrakConfig["fields"] as field, i}
          {#if field.name != "code"}
            <ComponentConfigNode
              node="{field}"
              bind:element="{scriptParams[field.name]}"
            />
          {/if}
        {/each}
      {/if}
    {:catch}
      <p>Failed to get config for RunScriptModifier!</p>
      <p>The back end server may be down.</p>
    {/await}
  </div>
  <div class="hbox">
    <div class="line-numbers">
      {#each loadedScript as _, index}
        <div>{index + 1}</div>
      {/each}
    </div>

    <span class="spacer"></span>

    <div class="textarea">
      <code>
        {@html hljs.highlight(loadedScript.join("\n"), {
          language: "python",
        }).value}
      </code>
    </div>
  </div>
  {#if errorMessage}
    <p class="error">
      Error:
      {errorMessage}
    </p>
  {/if}
  <div class="actions">
    <button on:click="{() => (runScriptPromise = runLoadedScript())}">
      {#await runScriptPromise}
        <Icon url="/icons/loading.svg" />
      {:then _}
        <!---->
      {:catch}
        <Icon url="/icons/error.svg" />
      {/await}
      Run script
    </button>
    <button on:click="{() => (modifierView = undefined)}">Cancel</button>
  </div>
</div>
