<style>
  .container {
    min-height: 100%;
    max-height: 100%;
    display: flex;
    flex-direction: column;
    flex-wrap: nowrap;
    justify-content: center;
    align-items: stretch;
    align-content: center;
    overflow: auto;
  }

  .inputs *:first-child {
    margin-top: 0;
  }

  .output {
    flex-grow: 1;
  }

  pre {
    white-space: pre-wrap;
  }

  .actions {
    margin-top: 2em;
    display: flex;
    flex-direction: row;
    flex-wrap: nowrap;
    justify-content: space-evenly;
    align-items: center;
    align-content: center;
  }

  input {
    background: inherit;
    color: inherit;
    border: none;
    border-bottom: 1px solid white;
    flex-grow: 1;
    margin-left: 1ch;
  }

  input:focus {
    outline: none;
    box-shadow: inset 0 -1px 0 var(--main-fg-color);
  }

  label {
    margin-bottom: 1em;
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
  import Button from "../utils/Button.svelte";
  import LoadingText from "../utils/LoadingText.svelte";

  import { selectedResource } from "../stores.js";

  export let modifierView;
  let apiUrl = JSON.parse(window.localStorage.getItem("aiApiUrl") ?? "null"),
    model = JSON.parse(window.localStorage.getItem("aiApiModel") ?? "null"),
    key = JSON.parse(window.localStorage.getItem("aiApiKey") ?? "null"),
    prompt;
  $: window.localStorage.setItem("aiApiUrl", JSON.stringify(apiUrl));
  $: window.localStorage.setItem("aiApiModel", JSON.stringify(model));
  $: window.localStorage.setItem("aiApiKey", JSON.stringify(key));

  function getSystemPrompt(r) {
    return r.get_config_for_component("LlmAnalyzer").then(({ fields }) => {
      for (const field of fields) {
        if (field.name == "system_prompt") {
          prompt = field.default;
          return field.default;
        }
      }
    });
  }

  $: promptPromise = getSystemPrompt($selectedResource);

  let resultPromise = undefined;
  function llmAnalyzer() {
    resultPromise = fetch(
      `${$selectedResource.uri}/run_component?component=LlmAnalyzer`,
      {
        credentials: "omit",
        body: JSON.stringify([
          "ofrak.core.llm.LlmAnalyzerConfig",
          {
            api_url: apiUrl,
            model: model,
            api_key: key || undefined,
            system_prompt: prompt,
          },
        ]),
        method: "POST",
        mode: "cors",
      }
    )
      .then(async (r) => {
        if (!r.ok) {
          throw Error(JSON.stringify(await r.json(), undefined, 2));
        }
        return await r.json();
      })
      .then((r) => {
        $selectedResource.attributes = $selectedResource.attributes;
        return r;
      })
      .then(({ modified: [{ attributes }] }) => {
        for (const [type, [_, { description }]] of attributes) {
          if (type == "ofrak.core.llm.LlmAttributes") {
            return description;
          }
        }
      });
  }
</script>

<div class="container">
  {#await promptPromise}
    <LoadingText />
  {:then _}
    <div class="inputs">
      <label>
        AI API URL
        <input type="text" bind:value="{apiUrl}" />
      </label>
      <label>
        AI Model
        <input type="text" bind:value="{model}" />
      </label>
      <label>
        AI API Key (Optional)
        <input type="password" bind:value="{key}" />
      </label>
      <label>
        System Prompt (Optional)
        <input type="text" value="{prompt}" />
      </label>
    </div>
  {:catch e}
    <p>{e}</p>
  {/await}
  <pre class="output">{#await resultPromise}
      <LoadingText />
    {:then result}
      {#if result}
        {result}
      {/if}
    {:catch e}
      {e}
    {/await}
  </pre>
  <div class="actions">
    <Button on:click="{llmAnalyzer}">Analyze</Button>
    <Button on:click="{() => (modifierView = undefined)}">Cancel</Button>
  </div>
</div>
