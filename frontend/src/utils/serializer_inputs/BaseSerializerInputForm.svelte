<style>
  .container {
    display: flex;
    flex-direction: column;
    flex-wrap: nowrap;
    justify-content: center;
    align-items: stretch;
    align-content: center;
  }

  .input {
    padding-left: 2em;
    padding-bottom: 0.5em;
    border-left: 1px dashed white;
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
