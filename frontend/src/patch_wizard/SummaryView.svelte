<style>
  .target-info-box {
    border: thin solid;
    margin-bottom: 1ch;
  }

  .target-info-header-bar {
    border: thin solid;
    font-size: medium;
    padding: 0.3em;
  }

  .refresh-button {
    margin-left: auto;
  }

  .summary-body {
    padding: 1em;
  }

  .warning {
    text-decoration-line: underline;
    text-decoration-color: red;
  }
</style>

<script>
  import ObjectWidget from "./ObjectWidget.svelte";
  import PatchSymbol from "./PatchSymbol.svelte";

  export let patchInfo;

  function buildSymbolRefMap(patchInfo) {
    let refMap = { allSyms: new Set() };

    for (const objInfo of patchInfo.objectInfos) {
      for (const sym of objInfo.strongSymbols) {
        if (refMap.hasOwnProperty(sym)) {
          refMap[sym].providedBy.push(objInfo.name);
        } else {
          refMap[sym] = {
            name: sym,
            providedBy: [objInfo.name],
            requiredBy: [],
          };
        }
        refMap.allSyms.add(sym);
      }
      for (const sym of objInfo.unresolvedSymbols) {
        if (refMap.hasOwnProperty(sym)) {
          refMap[sym].requiredBy.push(objInfo.name);
        } else {
          refMap[sym] = {
            name: sym,
            providedBy: [],
            requiredBy: [objInfo.name],
          };
        }
        refMap.allSyms.add(sym);
      }
    }

    for (const sym of patchInfo.targetInfo.symbols) {
      if (refMap.hasOwnProperty(sym)) {
        refMap[sym].providedBy.push("target binary");
      } else {
        refMap[sym] = {
          name: sym,
          providedBy: ["target binary"],
          requiredBy: [],
        };
      }
      refMap.allSyms.add(sym);
    }

    return refMap;
  }

  const symbolRefMap = buildSymbolRefMap(patchInfo);

  let totalBytes, nSegments, unresolvedSyms, unallocatedSegments;

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
    for (const symName of symbolRefMap.allSyms) {
      if (symbolRefMap[symName].providedBy.length === 0) {
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
  }

  updateSummary();
</script>

<div class="target-info-box">
  <div class="target-info-header-bar">
    SUMMARY <button class="refresh-button" on:click="{updateSummary}"
      >Refresh</button
    >
  </div>
  <div class="summary-body">
    {#if patchInfo.userInputs.toolchain}
      <p>
        Using {patchInfo.userInputs.toolchain.split(".").pop()}, 0x{totalBytes.toString(
          16
        )} bytes across
        {nSegments} segments will be injected into the target binary.
      </p>
    {:else}
      <p class="warning">No toolchain selected.</p>
    {/if}
    <p>Something about free space</p>
    {#if unallocatedSegments.length > 0}
      <p class="warning">
        {unallocatedSegments.length} segment(s) still need to be allocated:
      </p>
      {#each unallocatedSegments as [objName, segName]}
        <p>{objName}{segName}</p>
      {/each}
    {/if}
    <p>Target binary provides {patchInfo.targetInfo.symbols.length} symbols:</p>
    {#each patchInfo.targetInfo.symbols as sym}
      <PatchSymbol symbolInfo="{symbolRefMap[sym]}" />
    {/each}
    {#if unresolvedSyms.size > 0}
      <p class="warning">
        There are {unresolvedSyms.size} unresolved symbol(s)!
      </p>
      {#each Array.from(unresolvedSyms) as sym}
        <PatchSymbol symbolInfo="{symbolRefMap[sym]}" />
      {/each}
      <p>
        These symbols are referenced by the patch code, but not defined in the
        patch code or the binary.
      </p>
    {:else}
      <p>There are no unresolved symbols.</p>
    {/if}
  </div>
</div>
<div>
  {#each patchInfo.objectInfos as objInfo}
    <ObjectWidget objectInfo="{objInfo}" symbolRefMap="{symbolRefMap}" />
  {/each}
</div>
