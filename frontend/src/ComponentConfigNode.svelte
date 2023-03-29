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
</style>
<script>
  import Checkbox from "./Checkbox.svelte";
  export let node, element;
  let listElement, dictKey, dictValue, dataclassFields, unionTypeSelect;
  $: element;
  $: dataclassFields;
  console.log(node["type"])
  if(node["type"] == "typing.List" || node["type"] == "typing.Tuple" || (node["type"] == "typing.Dict")){
    element = [];
  }else if(node["type"] == "typing.Union"){
    unionTypeSelect = node["args"][0];
  }
  if(node["fields"] != null){
    dataclassFields = {}
    element = [node["type"], dataclassFields]
  }
  if(node["default"] != null){
    element = node["default"];
  }

  const addElementToArray = () => {
    element = [
      ... element,
      listElement
    ];
    element = element;
    listElement = null;
  };

  const addElementToDict = () => {
    element = [
      ... element,
      [dictKey, dictValue]
    ];
    element = element;
    dictKey = null;
    dictValue = null;
  };
</script>

<div class="container">
  {#if node["name"] != null}
    <p>{node["name"]}</p>
  {/if}

  {#if node["type"] == "builtins.bool"}
    <Checkbox bind:checked="{element}"/>
  {:else if node["type"] == "builtins.str"}
    <input bind:value="{element}"/>
  {:else if node["type"] == "builtins.int"}
    <input type=number bind:value={element}/>
  {:else if node["type"] == "typing.List" || node["type"] == "typing.Tuple"}
    {#each node["args"] as arg}
      <svelte:self node="{arg}" bind:element="{listElement}"/>
      <button on:click={addElementToArray}>Add Element</button>
    {/each}
    {#each element as elements}
      <span>{elements}</span>
    {/each}
  {:else if node["type"] == "typing.Dict"}
    <svelte:self node="{node["args"][0]}" bind:element="{dictKey}"/>
    <svelte:self node="{node["args"][1]}" bind:element="{dictValue}"/>
    <button on:click={addElementToDict}>Add Element</button>
  {:else if node["type"] == "typing.Union"}
    <p>Select Type</p>
    {#each node["args"] as type}
      <button on:click="{(e) => {unionTypeSelect = type}}">Use {type["type"]}</button>
    {/each}
    <svelte:self node="{unionTypeSelect}" bind:element={element}/>
  {:else if node["fields"] != null}
    {#each node["fields"] as field}
      <svelte:self node="{field}" bind:element="{dataclassFields[field["name"]]}"/>
    {/each}
  {/if}
</div>
