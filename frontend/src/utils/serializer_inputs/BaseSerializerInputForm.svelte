<style>
  .container {
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
  import PrimitivesInputForm from "./PrimitivesInputForm.svelte";
  import ListInputForm from "./ListInputForm.svelte";
  import TupleInputForm from "./TupleInputForm.svelte";
  import DictInputForm from "./DictInputForm.svelte";
  import UnionInputForm from "./UnionInputForm.svelte";
  import SourceBundleInputForm from "./SourceBundleInputForm.svelte";
  import EnumInputForm from "./EnumInputForm.svelte";
  import ObjectInputForm from "./ObjectInputForm.svelte";
  import { splitAndCapitalize } from "../../helpers";
  import BaseSerializerInputForm from "./BaseSerializerInputForm.svelte";

  const nodeTypeMap = {
    "builtins.bool": PrimitivesInputForm,
    "builtins.str": PrimitivesInputForm,
    "builtins.int": PrimitivesInputForm,
    "builtins.bytes": PrimitivesInputForm,
    "typing.List": ListInputForm,
    "typing.Iterable": ListInputForm,
    "typing.Tuple": TupleInputForm,
    "typing.Dict": DictInputForm,
    "typing.Union": UnionInputForm,
    "typing.Optional": UnionInputForm,
    "ofrak.core.patch_maker.modifiers.SourceBundle": SourceBundleInputForm,
  };

  export let node, element;

  function getFormType() {
    if (nodeTypeMap.hasOwnProperty(node.type)) {
      return nodeTypeMap[node.type];
    } else if (node.enum !== null) {
      return EnumInputForm;
    } else if (node.fields !== null) {
      return ObjectInputForm;
    } else {
      throw Error("Cannot determine form type for node " + node);
    }
  }

  const nodeName = node.name ? splitAndCapitalize(node.name) : "";
</script>

<div class="container">
  <div class="input">
    {#if node.name && !["builtins.bool", "builtins.str", "builtins.bytes", "builtins.int"].includes(node.type)}
      {nodeName}
    {/if}

    <svelte:component
      this="{getFormType()}"
      node="{node}"
      nodeName="{nodeName}"
      bind:element="{element}"
      baseForm="{BaseSerializerInputForm}"
    />
  </div>
</div>
