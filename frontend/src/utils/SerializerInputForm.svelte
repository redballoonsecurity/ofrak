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
    top: 0;
    left: 0;
    display: flex;
    flex-direction: row;
    flex-wrap: nowrap;
    align-items: start;
    justify-content: start;
  }
</style>

<script>
  import Checkbox from "./Checkbox.svelte";
  import { calculator, splitAndCapitalize } from "../helpers";
  import Icon from "./Icon.svelte";
  import FileBrowser from "./FileBrowser.svelte";
  import Button from "./Button.svelte";
  export let node, element;
  let unionTypeSelect,
    _element,
    intInput,
    files = null;
  let skip = [];

  const INT_PLACEHOLDERS = [
    "0x10 * 2 + 8",
    "(0x10 * 0x100 + 25) * 69",
    "0x3 + 5 - 0x2",
    "6 * 0x2 + 1",
    "0x4 * (0x2 + 2)",
    "12 / (0x3 * 0x2)",
    "0x7 - 0x2 * 0x3",
    "0x2 * (0x3 + 3)",
    "(0x2 ^ 3) - 1",
    "10 + 0x3 * 2",
    "0x3 * (0x2 + 2) + 2",
    "0x7 - 1 + 10",
  ];

  function doCalc() {
    try {
      element = calculator.calculate(_element);
      intInput?.setCustomValidity("");
    } catch {
      element = undefined;
      intInput?.setCustomValidity("Invalid expression.");
    }
  }

  $: if (node["type"] == "builtins.int") {
    doCalc(_element);
  }

  async function slurpSourceBundle(files) {
    for (const file of files) {
      let text = await file.text();
      element.push([file.name, text]);
    }
    return element;
  }

  $: if (files) {
    slurpSourceBundle(files);
  }

  function setArray() {
    element = _element.filter((e) => !skip.includes(e));
  }

  $: if (
    node["type"] == "typing.List" ||
    node["type"] == "typing.Tuple" ||
    node["type"] == "typing.Dict" ||
    node["type"] == "ofrak.core.patch_maker.modifiers.SourceBundle" ||
    node["type"] == "typing.Iterable"
  ) {
    setArray(_element, skip);
  }

  if (
    node["type"] == "typing.List" ||
    node["type"] == "typing.Tuple" ||
    node["type"] == "typing.Dict" ||
    node["type"] == "ofrak.core.patch_maker.modifiers.SourceBundle" ||
    node["type"] == "typing.Iterable"
  ) {
    _element = [];
  } else if (
    node["type"] == "typing.Union" ||
    node["type"] == "typing.Optional"
  ) {
    unionTypeSelect = node["args"][0];
  }

  function setName() {
    if (node?.type != null) {
      element = [node.type, {}];
    } else if (node["fields"] != null) {
      element = {};
    } else {
      element = [];
    }
  }

  $: if (node["type"].startsWith("ofrak") && node["enum"] == null) {
    setName();
  }

  const addElementToArray = () => {
    _element = [..._element, null];
  };

  const addElementToDict = () => {
    _element = [..._element, [null, null]];
  };

  if (node["type"] == "builtins.NoneType") {
    element = null;
  }

  $: nodeName = node["name"] ? splitAndCapitalize(node["name"]) : "";
</script>

<div class="container">
  <div class="input">
    {#if node["name"] && !["builtins.bool", "builtins.str", "builtins.bytes", "builtins.int"].includes(node["type"])}
      {nodeName}
    {/if}

    <!---->
    {#if node["type"] == "builtins.bool"}
      <Checkbox bind:checked="{element}" leftbox="{true}">
        {nodeName}
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
    {:else if node["type"] == "typing.List" || node["type"] == "typing.Iterable"}
      <div class="buttonbar">
        <Button
          --button-padding="0.5em 1em 0em 1em"
          on:click="{addElementToArray}"
        >
          <Icon url="/icons/plus.svg" />
        </Button>
      </div>
      {#each _element as elements}
        {#if !skip.includes(elements)}
          <div class="boxed">
            <div class="buttonbar">
              <Button
                --button-padding="0.5em 1em 0em 1em"
                on:click="{(e) => {
                  skip.push(elements);
                  skip = skip;
                }}"
              >
                <Icon url="/icons/error.svg" />
              </Button>
            </div>
            <svelte:self node="{node['args'][0]}" bind:element="{elements}" />
          </div>
        {/if}
      {/each}

      <!---->
    {:else if node["type"] == "typing.Tuple"}
      {#each node["args"] as arg, i}
        <svelte:self node="{arg}" bind:element="{element[i]}" />
      {/each}

      <!---->
    {:else if node["type"] == "typing.Dict"}
      <div class="buttonbar">
        <Button
          --button-padding="0.5em 1em 0em 1em"
          on:click="{addElementToDict}"
        >
          <Icon url="/icons/plus.svg" />
        </Button>
      </div>
      {#each _element as elements, index}
        {#if !skip.includes(elements)}
          <div class="boxed">
            <div class="buttonbar">
              <Button
                --button-padding="0.5em 1em 0em 1em"
                on:click="{(e) => {
                  skip.push(elements);
                  skip = skip;
                }}"
              >
                <Icon url="/icons/error.svg" />
              </Button>
              {elements}
            </div>
            <p>Key</p>
            <svelte:self
              node="{node['args'][0]}"
              bind:element="{elements[0]}"
            />
            <p>Value</p>
            <svelte:self
              node="{node['args'][1]}"
              bind:element="{elements[1]}"
            />
          </div>
        {/if}
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
    {:else if node["type"] == "ofrak.core.patch_maker.modifiers.SourceBundle"}
      <FileBrowser multiple="{true}" bind:files="{files}" />

      <!---->
    {:else if node["enum"] != null}
      <select bind:value="{element}">
        {#each Object.entries(node["enum"]) as [name, enum_value]}
          <option value="{enum_value}">
            {name}
          </option>
        {/each}
      </select>

      <!---->
    {:else if node["fields"] != null}
      {#each node["fields"] as field, i}
        {#if node["type"].startsWith("ofrak")}
          <svelte:self node="{field}" bind:element="{element[1][field.name]}" />
        {:else}
          <svelte:self node="{field}" bind:element="{element[field['name']]}" />
        {/if}
      {/each}
    {/if}
  </div>
</div>
