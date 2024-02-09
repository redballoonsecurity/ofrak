<style>
  .content {
    position: absolute;
    top: 0;
    height: 100%;
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
  import { selectedResource } from "../stores";
  import Breadcrumb from "../utils/Breadcrumb.svelte";
  import AssemblyView from "./AssemblyView.svelte";
  import DecompilationView from "./DecompilationView.svelte";
  import HexView from "../hex/HexView.svelte";
  import TextView from "./TextView.svelte";
  import SearchBar from "../utils/SearchBar.svelte";
  import { onMount } from "svelte";
  export let dataLenPromise, resourceNodeDataMap, resources;
  let display_type = "hex";
  let hasTextView = false;
  let hasAsmView = false;
  let hasDecompView = false;
  let dataSearchResults = {};
  let searchFunction;

  onMount(async () => {
    document.getElementById("hex").focus();
  });

  function checkTags() {
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
      "ofrak_angr.components.angr_decompilation_analyzer.AngrDecompilationAnalysisResource",
    ].some((tag) => $selectedResource.has_tag(tag));
  }
  $: checkTags($selectedResource);
</script>

<div class="content">
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
    <!-- TODO: Make search bar work for Asm, text, decomp -->
    <SearchBar
      bind:search="{searchFunction}"
      liveUpdate="{false}"
      showResultsWidgets="{true}"
      bind:searchResults="{dataSearchResults}"
    />
    <HexView
      dataLenPromise="{dataLenPromise}"
      resources="{resources}"
      bind:resourceNodeDataMap="{resourceNodeDataMap}"
      bind:searchFunction="{searchFunction}"
      dataSearchResults="{dataSearchResults}"
    />
  {:else if display_type == "text"}
    <hr />
    <TextView />
  {:else if display_type == "asm"}
    <hr />
    <AssemblyView bind:searchFunction="{searchFunction}" />
  {:else if display_type == "decomp"}
    <hr />
    <DecompilationView bind:searchFunction="{searchFunction}" />
  {/if}
</div>
