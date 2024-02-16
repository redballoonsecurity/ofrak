<style>
  .content {
    position: sticky;
    top: 0;
    height: 100%;
    width: 100%;
    overflow: hidden;
  }

  .breadcrumb {
    padding-bottom: 1em;
    background: var(--main-bg-color);
  }

  button {
    margin-bottom: 0;
    border: 1px solid white;
  }

  button:focus {
    border-bottom: 2px solid var(--main-bg-color);
  }

  .content hr {
    display: block;
    height: 1px;
    border: 0;
    border-top: 1px solid white;
    margin-top: -1px;
    padding: 0;
  }
</style>

<script>
  import { selectedResource, resourceNodeDataMap } from "../stores";
  import AssemblyView from "./AssemblyView.svelte";
  import DecompilationView from "./DecompilationView.svelte";
  import HexView from "../hex/HexView.svelte";
  import TextView from "./TextView.svelte";
  import { onMount } from "svelte";
  import Tabs from "../utils/Tabs.svelte";
  export let dataLenPromise, resources;
  let hasTextView = false;
  let hasAsmView = false;
  let hasDecompView = false;
  let tabs = [];

  onMount(async () => {
    document.getElementById("hex").focus();
  });

  const hexTab = {
    id: "hex",
    title: "Hex",
    component: HexView,
    props: {
      resources: resources,
      dataLenPromise: dataLenPromise,
    },
  };

  const textTab = {
    id: "text",
    title: "Text",
    component: TextView,
    props: {},
  };

  const asmTab = {
    id: "asm",
    title: "Assembly",
    component: AssemblyView,
    props: {},
  };

  const decompTab = {
    id: "decomp",
    title: "Decompilation",
    component: DecompilationView,
    props: {},
  };

  function checkTags() {
    tabs = [hexTab];
    hasTextView = ["ofrak.core.binary.GenericText"].some((tag) =>
      $selectedResource.has_tag(tag)
    );
    hasAsmView = [
      "ofrak.core.complex_block.ComplexBlock",
      "ofrak.core.basic_block.BasicBlock",
      "ofrak.core.instruction.Instruction",
      "ofrak.core.data.DataWord",
    ].some((tag) => $selectedResource.has_tag(tag));
    hasDecompView = [
      "ofrak_angr.components.angr_decompilation_analyzer.AngrDecompilationAnalysis",
    ].some((tag) => $selectedResource.has_tag(tag));
    if (hasTextView) {
      tabs.push(textTab);
    }
    if (hasAsmView) {
      tabs.push(asmTab);
    }
    if (hasDecompView) {
      tabs.push(decompTab);
    }
  }
  $: checkTags($selectedResource);
</script>

<Tabs tabs="{tabs}" initTabId="hex" />

<!-- <div class="content">
  <div class="breadcrumb">
    <Breadcrumb />
  </div>
  <div class="tabs">
    <button
      id="hex"
      on:click="{(e) => {
        display_type = 'hex';
      }}">Hex</button
    >
    {#if hasTextView}
      <button
        id="text"
        on:click="{(e) => {
          display_type = 'text';
        }}">Text</button
      >
    {/if}
    {#if hasAsmView}
      <button
        id="asm"
        on:click="{(e) => {
          display_type = 'asm';
        }}">Asm</button
      >
    {/if}
    {#if hasDecompView}
      <button
        id="decomp"
        on:click="{(e) => {
          display_type = 'decomp';
        }}">Decompilation</button
      >
    {/if}
  </div>
  {#if display_type == "hex"}
    <hr />
    <HexView
      dataLenPromise="{dataLenPromise}"
      resources="{resources}"
    />
  {:else if display_type == "text"}
    <hr />
    <TextView />
  {:else if display_type == "asm"}
    <hr />
    <AssemblyView />
  {:else if display_type == "decomp"}
    <hr />
    <DecompilationView />
  {/if}
</div> -->
