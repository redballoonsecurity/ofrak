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

  input {
    background: inherit;
    color: inherit;
    border: none;
    border-bottom: 1px solid white;
    flex-grow: 1;
    margin-left: 1ch;
  }

  li {
    margin-bottom: 1em;
    display: flex;
    flex-direction: row;
    flex-wrap: nowrap;
    justify-content: space-evenly;
    align-items: baseline;
    align-content: left;
    white-space: nowrap;
  }
  input:focus {
    outline: none;
    box-shadow: inset 0 -1px 0 var(--main-fg-color);
  }

  /* Hide spinner buttons for numeric inputs
     Source: https://stackoverflow.com/questions/3790935/can-i-hide-the-html5-number-input-s-spin-box/4298216#4298216 */
  input::-webkit-outer-spin-button,
  input::-webkit-inner-spin-button {
    -webkit-appearance: none;
    margin: 0;
  }

  input[type="number"] {
    -moz-appearance: textfield;
  }
</style>

<script>
  import Checkbox from "./Checkbox.svelte";
  export let node, element, optional;
  let listElement, dictKey, dictValue, dataclassFields, unionTypeSelect;
  $: element;
  $: dataclassFields;
  $: unionTypeSelect;
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
</script>

<div class="container">
  <div class="inputs">
    {#if node["type"] == "typing.Optional"}
      {#each node["args"] as arg}
        <svelte:self node="{arg}" optional="true" bind:element="{element}" />
      {/each}
    {:else if node["type"] == "builtins.bool"}
      <li>
        <Checkbox bind:checked="{element}" />
      </li>
    {:else if node["type"] == "builtins.str"}
      <li>
        <input bind:value="{element}" />
      </li>
    {:else if node["type"] == "builtins.bytes"}
      <li>
        <input bind:value="{element}" />
      </li>
    {:else if node["type"] == "builtins.int"}
      <li>
        <input type="number" bind:value="{element}" />
      </li>
    {:else if node["type"] == "typing.List"}
      <li>
        {#each node["args"] as arg}
          <svelte:self node="{arg}" bind:element="{listElement}" />
          <button on:click="{addElementToArray}">Add Element</button>
        {/each}
      </li>
      {#each element as elements}
        <li>{elements}</li>
      {/each}
    {:else if node["type"] == "typing.Tuple"}
      <li>
        {#each node["args"] as arg, i}
          <svelte:self node="{arg}" bind:element="{element[i]}" />
        {/each}
      </li>
      <li>{element}</li>
    {:else if node["type"] == "typing.Dict"}
      <li>
        <button on:click="{addElementToDict}">Add Element</button>
        <p>Key</p>
        <svelte:self node="{node['args'][0]}" bind:element="{dictKey}" />
        <p>Value</p>
        <svelte:self node="{node['args'][1]}" bind:element="{dictValue}" />
      </li>
      {#each element as elements}
        <li>{elements}</li>
      {/each}
    {:else if node["type"] == "typing.Union"}
      <p>Select Type</p>
      <form class="dropdown">
        <select
          on:click="{() => undefined}"
          bind:value="{unionTypeSelect}"
        >
          <option value="{null}">{node["args"][0]}</option>
          {#each node["args"] as arg}
            <option value="{arg}">
              {arg.type}
            </option>
          {/each}
        </select>
      </form>
      <svelte:self node="{unionTypeSelect}" bind:element="{element}" />
    {:else if node["enum"] != null}
      <form class="dropdown">
        <select
          on:click|stopPropagation="{() => undefined}"
          bind:value="{element}"
        >
          <option value="{null}">{node["enum"][0]}</option>
          {#each Object.entries(node["enum"]) as [name, value]}
            <option value="{node['type']}.{name}">
              {name}
            </option>
          {/each}
        </select>
      </form>
    {:else if node["fields"] != null}
      {#each node["fields"] as field, i}
        {#if node["type"] == "ofrak_type.range.Range"}
          {field["name"]}: <svelte:self
            node="{field}"
            bind:element="{element[i]}"
          />
        {:else}
          {field["name"]}: <svelte:self
            node="{field}"
            bind:element="{element[field['name']]}"
          />
        {/if}
      {/each}
    {/if}
  </div>
</div>
