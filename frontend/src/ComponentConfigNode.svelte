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
</style>

<script>
  import Checkbox from "./Checkbox.svelte";
  import { calculator } from "./helpers";
  export let node, element, optional;
  let listElement,
    dictKey,
    dictValue,
    dataclassFields,
    unionTypeSelect,
    _element;

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
    node["type"] == "typing.Dict"
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
  if (optional) {
    element = null;
  }

  const addElementToArray = () => {
    element = [...element, listElement];
    element = element;
    listElement = null;
  };

  const addElementToDict = () => {
    element = [...element, [dictKey, dictValue]];
    element = element;
    dictKey = null;
    dictValue = null;
  };

  $: nodeName = node["name"] ? node["name"] + ":" : "";
</script>

<div class="container">
  <div class="input">
    {#if node["name"] && !["builtins.bool", "builtins.str", "builtins.bytes", "builtins.int"].includes(node["type"])}
      {node["name"]}:
    {/if}

    {#if node["type"] == "typing.Optional"}
      {#each node["args"] as arg}
        <svelte:self node="{arg}" optional="true" bind:element="{element}" />
      {/each}

      <!---->
    {:else if node["type"] == "builtins.bool"}
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
      {#each node["args"] as arg}
        <svelte:self node="{arg}" bind:element="{listElement}" />
        <button on:click="{addElementToArray}">Add Element</button>
      {/each}
      {#each element as elements}
        {elements}
      {/each}

      <!---->
    {:else if node["type"] == "typing.Tuple"}
      {#each node["args"] as arg, i}
        <svelte:self node="{arg}" bind:element="{element[i]}" />
      {/each}
      {element}

      <!---->
    {:else if node["type"] == "typing.Dict"}
      <button on:click="{addElementToDict}">Add Element</button>
      <div class="boxed">
        <p>Key</p>
        <svelte:self node="{node['args'][0]}" bind:element="{dictKey}" />
        <p>Value</p>
        <svelte:self node="{node['args'][1]}" bind:element="{dictValue}" />
        {#each element as elements}
          {elements}
        {/each}
      </div>

      <!---->
    {:else if node["type"] == "typing.Union"}
      <p>Select Type</p>
      <select bind:value="{unionTypeSelect}">
        {#each node["args"] as arg}
          <option value="{arg}">
            {arg.type}
          </option>
        {/each}
      </select>
      <svelte:self node="{unionTypeSelect}" bind:element="{element}" />

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
