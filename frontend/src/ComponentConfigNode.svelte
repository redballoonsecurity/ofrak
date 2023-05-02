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

  .container {
    min-height: 100%;
    display: flex;
    flex-direction: column;
    flex-wrap: nowrap;
    justify-content: center;
    align-items: stretch;
    align-content: center;
  }

  label {
    display: flex;
    flex-direction: row;
    flex-wrap: nowrap;
    justify-content: flex-start;
    align-items: baseline;
  }

  input {
    background: inherit;
    color: inherit;
    border: none;
    border-bottom: 1px solid var(--main-fg-color);
    flex-grow: 1;
    margin-left: 1ch;
    /* width: 100%;
    margin: 0;
    padding: 0; */
  }

  input:invalid {
    border-bottom: 1px solid var(--comment-color);
  }

  input:focus {
    outline: none;
    box-shadow: inset 0 -1px 0 var(--main-fg-color);
  }

  input:focus:invalid {
    outline: none;
    box-shadow: inset 0 -1px 0 var(--comment-color);
  }

  .input {
    padding-left: 2em;
    padding-bottom: 0.5em;
    border-left: 1px dashed white;
  }

  select {
    background-color: var(--main-bg-color);
    color: inherit;
    border: 1px solid;
    border-color: inherit;
    border-radius: 0;
    padding: 0.5em 1em;
    margin-left: 0.5em;
    margin-right: 0.5em;
    font-size: inherit;
    font-family: var(--font);
    box-shadow: none;
  }

  select {
    width: 100%;
    margin: 0;
    margin-bottom: 1em;
  }

  option {
    font-family: monospace;
  }

  .boxed {
    border: 2px solid var(--main-fg-color);
    padding: 2em;
    margin: 1em 0 2em 0;
  }

  .buttonbar {
    position: sticky;
    top: 0;
    left: 0;
    display: flex;
    flex-direction: row;
    flex-wrap: nowrap;
    align-items: start;
    justify-content: start;
  }
  .buttonbar button{
    display: flex;
    align-items: start;
    justify-content: start;
    flex-direction: row;
  }
</style>

<script>
  import Checkbox from "./Checkbox.svelte";
  import { calculator } from "./helpers";
  import Icon from "./Icon.svelte";
  export let node, element;
  let unionTypeSelect, _element;

  const INT_PLACEHOLDERS = ["0x10 * 2 + 8", "(0x10 * 0x100 + 25) * 69"];

  $: if (node["type"] == "builtins.int") {
    try {
      element = calculator.calculate(_element);
    } catch {
      element = undefined;
    }
  }

  if (
    node["type"] == "typing.List" ||
    node["type"] == "typing.Tuple" ||
    node["type"] == "typing.Dict" ||
    node["type"] == "ofrak.core.patch_maker.modifiers.SourceBundle"
  ) {
    element = [];
  } else if (node["type"] == "typing.Union") {
    unionTypeSelect = node["args"][0];
  }
  if (node["type"] == "ofrak_type.range.Range") {
    element = [];
  } else if (node["fields"] != null) {
    element = {};
  }
  if (node["default"] != null) {
    element = node["default"];
  }

  const addElementToArray = () => {
    element = [...element, null];
    element = element;
  };

  const addElementToDict = () => {
    element = [...element, [null, null]];
    element = element;
  };

  $: if (node["type"] == "ofrak.core.patch_maker.modifiers.SourceBundle") {
    node = {
      name: node["name"],
      type: "typing.Dict",
      args: [
        {
          name: null,
          type: "builtins.str",
          args: null,
          fields: null,
          enum: null,
          default: null,
        },
        {
          name: null,
          type: "typing.Union",
          args: [
            {
              name: null,
              type: "builtins.bytes",
              args: null,
              fields: null,
              enum: null,
              default: null,
            },
            {
              name: null,
              type: "ofrak.core.patch_maker.modifiers.SourceBundle",
              args: null,
              fields: null,
              enum: null,
              default: null,
            },
          ],
          fields: null,
          enum: null,
          default: null,
        },
      ],
      fields: null,
      enum: null,
      default: null,
    };
  }

  $: nodeName = node["name"] ? node["name"] + ":" : "";
</script>

<div class="container">
  <div class="input">
    {#if node["name"] && !["builtins.bool", "builtins.str", "builtins.bytes", "builtins.int"].includes(node["type"])}
      {node["name"]}:
    {/if}

    <!---->
    {#if node["type"] == "builtins.bool"}
      <Checkbox bind:checked="{element}" leftbox="{true}">
        {node["name"]}
      </Checkbox>

      <!---->
    {:else if node["type"] == "builtins.str"}
      <label>
        {nodeName}
        <input bind:value="{element}" />
      </label>

      <!---->
    {:else if node["type"] == "builtins.bytes"}
      <label>
        {nodeName}
        <input
          pattern="([0-9a-fA-F][0-9a-fA-F])*"
          placeholder="00deadbeef00"
          bind:value="{element}"
        />
      </label>

      <!---->
    {:else if node["type"] == "builtins.int"}
      <label>
        {nodeName}
        <input
          placeholder="{INT_PLACEHOLDERS[
            Math.floor(Math.random() * INT_PLACEHOLDERS.length)
          ]}"
          bind:value="{_element}"
        />
      </label>

      <!---->
    {:else if node["type"] == "typing.List"}
      <div class="buttonbar">
        <button class="add" on:click="{addElementToArray}">Add</button>
      </div>
      {#each element as elements}
        <div class="boxed">
          <div class="buttonbar">
            <button class="remove"
              on:click="{(e) => {
                element = element.filter((x) => x !== elements);
              }}">
              <Icon url="/icons/error.svg" />
            </button
            >
          </div>
          <svelte:self node="{node["args"][0]}" bind:element="{elements}" />

        </div>
      {/each}

      <!---->
    {:else if node["type"] == "typing.Tuple"}
      {#each node["args"] as arg, i}
        <svelte:self node="{arg}" bind:element="{element[i]}" />
      {/each}

      <!---->
    {:else if node["type"] == "typing.Dict"}
      <div class="buttonbar">
        <button class="add" on:click="{addElementToDict}">Add</button>
      </div>
      {#each Object.entries(element) as [key, value]}
        <div class="boxed">
          <div class="buttonbar">
              <button class="remove"
              on:click="{(e) => {
                element = delete element[key] && element;
              }}">
              <Icon url="/icons/error.svg" />
              </button
            >
          </div>
          <p>Key</p>
          <svelte:self node="{node['args'][0]}" bind:element="{key}" />
          <p>Value</p>
          <svelte:self node="{node['args'][1]}" bind:element="{value}" />
        </div>
      {/each}

      <!---->
    {:else if node["type"] == "typing.Union" || node["type"] == "typing.Optional"}
      <select bind:value="{unionTypeSelect}">
        {#each node["args"] as arg}
          <option value="{arg}">
            {arg.type}
          </option>
        {/each}
      </select>
      {#if unionTypeSelect != null}
        <svelte:self node="{unionTypeSelect}" bind:element="{element}" />
      {/if}

      <!---->
    {:else if node["enum"] != null}
      <select bind:value="{element}">
        {#each Object.entries(node["enum"]) as [name, value]}
          <option value="{node['type']}.{name}">
            {name}
          </option>
        {/each}
      </select>

      <!---->
    {:else if node["fields"] != null}
      {#each node["fields"] as field, i}
        {#if node["type"] == "ofrak_type.range.Range"}
          <svelte:self node="{field}" bind:element="{element[i]}" />
        {:else}
          <svelte:self node="{field}" bind:element="{element[field['name']]}" />
        {/if}
      {/each}
    {/if}
  </div>
</div>
