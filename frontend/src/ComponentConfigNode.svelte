<style>
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
</style>

<script>
  import Checkbox from "./Checkbox.svelte";
  export let node, element;
  let listElement, dictKey, dictValue, dataclassFields, unionTypeSelect;
  $: element;
  $: dataclassFields;
  console.log(node["type"]);
  if (
    node["type"] == "typing.List" ||
    node["type"] == "typing.Tuple" ||
    node["type"] == "typing.Dict"
  ) {
    element = [];
  } else if (node["type"] == "typing.Union") {
    unionTypeSelect = node["args"][0];
  }
  if (node["fields"] != null) {
    dataclassFields = {};
    element = [node["type"], dataclassFields];
  }
  if (node["default"] != null) {
    element = node["default"];
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
    {#if node["type"] == "builtins.bool"}
      <li>
        {#if node["name"] != null}
          {node["name"]}
        {/if}
        <Checkbox bind:checked="{element}" />
      </li>
    {:else if node["type"] == "builtins.str"}
      <li>
        {#if node["name"] != null}
          {node["name"]}
        {/if}
        <input bind:value="{element}" />
      </li>
    {:else if node["type"] == "builtins.int"}
      <li>
        {#if node["name"] != null}
          {node["name"]}
        {/if}
        <input type="number" bind:value="{element}" />
      </li>
    {:else if node["type"] == "typing.List" || node["type"] == "typing.Tuple"}
      <li>
        {#if node["name"] != null}
          {node["name"]}
        {/if}
        {#each node["args"] as arg}
          <svelte:self node="{arg}" bind:element="{listElement}" />
          <button on:click="{addElementToArray}">Add Element</button>
        {/each}
      </li>
      {#each element as elements}
        <li>{elements}</li>
      {/each}
    {:else if node["type"] == "typing.Dict"}
      <li>
        {#if node["name"] != null}
          {node["name"]}
        {/if}
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
      {#each node["args"] as type}
        <button
          on:click="{(e) => {
            unionTypeSelect = type;
          }}">Use {type["type"]}</button
        >
      {/each}
      <svelte:self node="{unionTypeSelect}" bind:element="{element}" />
    {:else if node["fields"] != null}
      {#each node["fields"] as field}
        <svelte:self
          node="{field}"
          bind:element="{dataclassFields[field['name']]}"
        />
      {/each}
    {/if}
  </div>
</div>
