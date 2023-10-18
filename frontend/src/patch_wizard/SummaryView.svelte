<style>
  .summary-info-header-bar {
    border: thin solid;
    font-size: medium;
    padding: 0.3em;
    display: flex;
    align-items: center;
  }

  .refresh-button {
    margin-left: auto;
  }

  .summary-body {
    padding-top: 1em;
  }

  .warning {
    text-decoration-line: underline;
    text-decoration-color: red;
  }
</style>

<script>
  import PatchSymbol from "./PatchSymbol.svelte";
  import SummaryWidget from "./SummaryWidget.svelte";
  import Button from "../utils/Button.svelte";
  import ToolchainSetupView from "./ToolchainSetupView.svelte";
  import SourceMenuView from "./SourceMenuView.svelte";
  import ObjectMappingView from "./ObjectMappingView.svelte";

  export let patchInfo, subMenu;

  let totalBytes, nSegments, unresolvedSyms, unallocatedSegments, nSources;

  function validVaddr(vaddr) {
    return vaddr || 0 === vaddr;
  }

  function updateSummary() {
    totalBytes = 0;
    nSegments = 0;
    for (const obj of patchInfo.objectInfos) {
      for (const seg of obj.segments) {
        if (seg.include) {
          totalBytes += seg.size;
          nSegments++;
        }
      }
    }

    unresolvedSyms = new Set();
    for (const symName of patchInfo.symbolRefMap.allSyms) {
      if (patchInfo.symbolRefMap[symName].providedBy.length === 0) {
        unresolvedSyms.add(symName);
      }
    }

    unallocatedSegments = [];
    for (const obj of patchInfo.objectInfos) {
      for (const seg of obj.segments) {
        if (seg.include && !validVaddr(seg.allocatedVaddr)) {
          unallocatedSegments.push([obj.name, seg.name]);
        }
      }
    }

    nSources = patchInfo.sourceInfos.length;
  }

  async function updatePatchPlacement() {
    console.log("Rebuild BOM, fetch updated objectInfos");
    console.log(
      "If that succeeds, here is where the updateObjectInfos gets called"
    );
    updateSummary();
  }

  async function updateSymbolDefines() {
    if (!patchInfo.objectInfosValid) {
      await updatePatchPlacement();
    }

    console.log("Rebuild target BOM, fetch that (for its stubbed symbols)");
    console.log(
      "If that succeeds, here is where the buildSymbolRefMap gets called"
    );
    updateSummary();
  }

  updateSummary();
</script>

<div class="summary-info-header-bar">
  OVERVIEW <button class="refresh-button" on:click="{updateSummary}"
    >Refresh</button
  >
</div>
<div class="summary-body">
  <SummaryWidget
    title="Step 1. Toolchain & Patch Source"
    markError="{!(patchInfo.userInputs.toolchain && nSources > 0)}"
    valid="{true}"
    updateFunction="{() => {}}"
  >
    {#if patchInfo.userInputs.toolchain && nSources}
      <p>
        Using {patchInfo.userInputs.toolchain.split(".").pop()} to build patch from
        {nSources} source code files.
      </p>
    {:else if nSources}
      <p class="warning">No toolchain selected</p>
      <p>to build {nSources} source code files.</p>
    {:else if patchInfo.userInputs.toolchain}
      <p>Using {patchInfo.userInputs.toolchain.split(".").pop()}</p>
      <p class="warning">but no source code files to build patch from!</p>
    {:else}
      <p class="warning">
        No toolchain selected and no source code files provided!
      </p>
    {/if}
    <br />
    <Button on:click="{() => (subMenu = ToolchainSetupView)}"
      >Configure Toolchain</Button
    >
    <Button on:click="{() => (subMenu = SourceMenuView)}"
      >Configure Patch Sources</Button
    >
  </SummaryWidget>
  <SummaryWidget
    title="Step 2. Patch Placement"
    markError="{nSegments || unallocatedSegments.length > 0}"
    valid="{patchInfo.objectInfosValid}"
    updateFunction="{updatePatchPlacement}"
  >
    <p>Something about free space</p>
    {#if nSegments}
      <p>
        {nSegments} segment{nSegments > 1 ? "s" : ""} totaling 0x{totalBytes.toString(
          16
        )} bytes will be extracted from the compiled sources and injected into the
        target binary at unique addresses.
      </p>
    {:else}
      <p class="warning">No segments chosen for injection!</p>
    {/if}
    {#if unallocatedSegments.length > 0}
      <p class="warning">
        {unallocatedSegments.length} segment(s) still need to be allocated:
      </p>
      {#each unallocatedSegments as [objName, segName]}
        <p>{objName}{segName}</p>
      {/each}
    {/if}
    <br />
    <Button on:click="{() => (subMenu = null)}">Create Free Space</Button>
    <Button on:click="{() => (subMenu = ObjectMappingView)}"
      >Configure Patch Placement</Button
    >
  </SummaryWidget>
  <SummaryWidget
    title="Step 3. Symbol Definitions"
    markError="{unresolvedSyms.size > 0}"
    valid="{patchInfo.targetInfoValid}"
    updateFunction="{updateSymbolDefines}"
  >
    <p>
      Target binary provides {patchInfo.targetInfo.symbols.length} symbols:
    </p>
    {#each patchInfo.targetInfo.symbols as sym}
      <PatchSymbol symbolInfo="{patchInfo.symbolRefMap[sym]}" />
    {/each}
    {#if unresolvedSyms.size > 0}
      <p class="warning">
        There are {unresolvedSyms.size} unresolved symbol(s)!
      </p>
      {#each Array.from(unresolvedSyms) as sym}
        <PatchSymbol symbolInfo="{patchInfo.symbolRefMap[sym]}" />
      {/each}
      <p>
        These symbols are referenced by the patch code, but not defined in the
        patch code or the binary.
      </p>
    {:else}
      <p>There are no unresolved symbols.</p>
    {/if}
    <br />
    <Button on:click="{() => (subMenu = null)}">Define Symbols Manually</Button>
  </SummaryWidget>
</div>
