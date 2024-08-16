<style>
  select,
  option {
    background-color: var(--main-bg-color);
    color: inherit;
    border: 1px solid;
    border-color: inherit;
    border-radius: 0;
    padding-top: 0.5em;
    padding-bottom: 0.5em;
    padding-left: 1em;
    padding-right: 1em;
    font-size: inherit;
    font-family: var(--font);
    box-shadow: none;
  }

  .inputs > *:nth-child(1) {
    margin: 0 0 1em 0;
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
    max-height: 100%;
    min-height: 100%;
  }

  .container {
    display: flex;
    flex-direction: column;
    flex-wrap: nowrap;
    justify-content: flex-start;
    align-items: flex-start;
    max-height: 100%;
    min-height: 100%;
    overflow: auto;
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

  .scriptchoice {
    display: block;
  }

  .scriptchoice > * {
    display: inline-flex;
  }
</style>

<script>
  import FileBrowser from "../utils/FileBrowser.svelte";
  import LoadingText from "../utils/LoadingText.svelte";
  import SerializerInputForm from "../utils/SerializerInputForm.svelte";
  import Icon from "../utils/Icon.svelte";
  import Button from "../utils/Button.svelte";

  import hljs from "highlight.js";
  import python from "highlight.js/lib/languages/python";

  import {
    selected,
    selectedResource,
    selectedProject,
    settings,
    resourceNodeDataMap,
  } from "../stores";
  import { onMount } from "svelte";

  hljs.registerLanguage("python", python);

  export let modifierView;
  let runScriptPromise = Promise.resolve(null),
    files = null,
    projectScript = null,
    loadedScript = [],
    errorMessage,
    ofrakConfigsPromise = new Promise(() => {}),
    scriptParams = {};

  $: if (files) {
    files[0].text().then((value) => {
      loadedScript = value.split("\n");
    });
  }

  $: if (projectScript) {
    fetch(
      `${$settings.backendUrl}/get_project_script?project=${$selectedProject.session_id}&script=${projectScript}`
    ).then((r) => {
      if (!r.ok) {
        throw Error(r.statusText);
      }
      r.text().then((r) => {
        loadedScript = r.split("\n");
      });
    });
  }

  async function runLoadedScript() {
    let results = {};
    try {
      results = await $selectedResource.run_component(
        "RunScriptModifier",
        "ofrak.core.run_script_modifier.RunScriptModifierConfig",
        Object.assign({ code: loadedScript.join("\n") }, scriptParams)
      );
    } catch (err) {
      $selectedResource.flush_cache();
      throw err;
    }
    for (const result in results) {
      if (result === "modified") {
        for (const resource of results[result]) {
          if (!$resourceNodeDataMap[resource["id"]]) {
            $resourceNodeDataMap[resource["id"]] = {};
          }
          $resourceNodeDataMap[resource["id"]].lastModified = true;
        }
      }
    }
    return results;
  }

  function parseError(err) {
    try {
      const parsed = JSON.parse(err.message);
      return `${parsed.type}: ${parsed.message}`;
    } catch (_) {
      return `Error: ${err.message}`;
    }
  }

  onMount(async () => {
    ofrakConfigsPromise =
      $selectedResource.get_config_for_component("RunScriptModifier");
  });
</script>

<link rel="stylesheet" href="./code.css" />

<div class="container">
  <div class="inputs">
    <div class="scriptchoice">
      {#if $selectedProject && $selectedProject.loaded}
        <select
          on:click="{(e) => {
            e.stopPropagation();
          }}"
          bind:value="{projectScript}"
        >
          <option value="{null}" selected disabled
            >Select script from Project</option
          >
          {#each $selectedProject.binaries[$selectedProject.loaded[$selected]].associated_scripts as script}
            <option value="{script}">
              {script}
            </option>
          {/each}
        </select>
        <p>OR</p>
      {/if}
      <div><FileBrowser multiple="{false}" bind:files="{files}" /></div>
    </div>
    {#await ofrakConfigsPromise}
      <LoadingText />
    {:then ofrakConfig}
      {#if ofrakConfig.length != 0}
        {#each ofrakConfig["fields"] as field, i}
          {#if field.name != "code"}
            <SerializerInputForm
              node="{field}"
              bind:element="{scriptParams[field.name]}"
            />
          {/if}
        {/each}
      {/if}
    {:catch err}
      <p>Failed to get config for RunScriptModifier!</p>
      <p>The back end server may be down.</p>
      <p class="error">
        Error:
        {parseError(err)}
      </p>
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
  {#await runScriptPromise}
    <!---->
  {:then results}
    {#if results}
      <p>
        Success! {results.modified.length} resource{#if results.modified.length !== 1}s{/if}
        modified.
      </p>
    {/if}
  {:catch err}
    <p class="error">
      Error:
      {parseError(err)}
    </p>
  {/await}
  <div class="actions">
    <Button on:click="{() => (runScriptPromise = runLoadedScript())}">
      {#await runScriptPromise}
        <Icon url="/icons/loading.svg" />
      {:then _}
        <!---->
      {:catch _}
        <Icon url="/icons/error.svg" />
      {/await}
      Run script
    </Button>
    <Button
      on:click="{() => {
        modifierView = undefined;
        const orig_selected = $selected;
        $selected = undefined;
        $selected = orig_selected;
        if (!$resourceNodeDataMap[$selected]) {
          $resourceNodeDataMap[$selected] = {};
        }
        $resourceNodeDataMap[$selected].collapsed = false;
        $resourceNodeDataMap[$selected].childrenPromise =
          $selectedResource?.get_children();
      }}">Back</Button
    >
  </div>
</div>
