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

  .nav-bar {
    display: inline-flex;
    align-items: center;
  }
</style>

<script>
  import { onMount } from "svelte";

  import Split from "../utils/Split.svelte";
  import Pane from "../utils/Pane.svelte";
  import Button from "../utils/Button.svelte";

  import {
    popViewCrumb,
    selectedResource,
    settings,
    viewCrumbs,
  } from "../stores";
  import {
    fakeFetchObjectInfos,
    fakeFetchTargetInfo,
    fakePatchInfo,
  } from "./dev_consts";
  import SourceMenuView from "./SourceMenuView.svelte";
  import ObjectMappingView from "./ObjectMappingView.svelte";
  import ToolchainSetupView from "./ToolchainSetupView.svelte";
  import SummaryWidget from "./SummaryWidget.svelte";
  import PatchSymbol from "./PatchSymbol.svelte";
  import SymbolView from "./SymbolView.svelte";
  import PatchMakerLogsView from "./PatchMakerLogsView.svelte";
  import Loading from "../utils/LoadingText.svelte";

  async function fetchPatchesInProgress() {
    let r = await fetch(
      `${$settings.backendUrl}/patch_wizard/get_all_patches_in_progress`,
      {
        method: "POST",
        headers: {
          "Content-Type": "application/json",
        },
        body: "",
      }
    );
    if (!r.ok) {
      throw Error(JSON.stringify(await r.json(), undefined, 2));
    }

    return await r.json();
  }

  async function fetchObjectInfos(patchName, toolchain, toolchainConfig) {
    let r = await fetch(
      `${$settings.backendUrl}/patch_wizard/get_object_infos?patch_name=${patchName}`,
      {
        method: "POST",
        headers: {
          "Content-Type": "application/json",
        },
        body: JSON.stringify({
          toolchain: toolchain,
          toolchainConfig: toolchainConfig,
        }),
      }
    );
    if (!r.ok) {
      throw Error(JSON.stringify(await r.json(), undefined, 2));
    }
    return await r.json();
  }

  async function fetchTargetInfo(patchName) {
    let r = await fetch(
      `${$settings.backendUrl}/patch_wizard/get_target_info?patch_name=${patchName}`,
      {
        method: "POST",
        headers: {
          "Content-Type": "application/json",
        },
      }
    );
    if (!r.ok) {
      throw Error(JSON.stringify(await r.json(), undefined, 2));
    }
    return await r.json();
  }

  async function doPatch(patchInfo) {
    addLogBreak();
    let r = await fetch(
      `${$settings.backendUrl}/patch_wizard/inject_patch?patch_name=${patchInfo.name}`,
      {
        method: "POST",
        headers: {
          "Content-Type": "application/json",
        },
        body: JSON.stringify({
          objectInfos: patchInfo.objectInfos,
          userSymbols: patchInfo.userInputs.symbols,
        }),
      }
    );
    if (!r.ok) {
      throw Error(JSON.stringify(await r.json(), undefined, 2));
    }
    return await r.json();
  }

  let subMenu = undefined;
  let addLogBreak;

  let overview = {
    totalBytes: 0,
    nSegments: 0,
    unresolvedSyms: new Set(),
    unallocatedSegments: [],
    nSources: 0,
  };

  let patchInfo;

  function assignSegmentColors(patchInfo) {
    let idx = 0;
    for (const obj of patchInfo.objectInfos) {
      for (const seg of obj.segments) {
        seg.color = $settings.colors[idx];
        if (idx++ >= $settings.colors.length) {
          idx = 0;
        }
      }
    }
  }

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

    for (const [symName, symVal] of patchInfo.userInputs.symbols) {
      if (refMap.hasOwnProperty(symName)) {
        refMap[symName].providedBy.push("user input");
      } else {
        refMap[symName] = {
          name: symName,
          providedBy: ["user input"],
          requiredBy: [],
        };
      }
      refMap.allSyms.add(symName);
    }

    return refMap;
  }

  function importObjectInfos(updatedObjectInfos) {
    // May mutate updatedObjectInfos

    // Keep track of when source files were renamed, but their object placements should still be preserved
    const currentObjNames = new Map();
    for (const sourceInfo of patchInfo.sourceInfos) {
      if (sourceInfo.originalName) {
        currentObjNames.set(sourceInfo.originalName, sourceInfo.name);
      } else {
        currentObjNames.set(sourceInfo.name, sourceInfo.name);
      }
    }

    // Map from current object names -> old object mappings
    let previousObjectSegmentInfos = new Map();
    // Carry over segment mapping and inclusion info from previous configuration
    // Allows for iterative patch development without losing all patch situation work
    if (patchInfo.objectInfos) {
      for (const objInfo of patchInfo.objectInfos) {
        for (const segInfo of objInfo.segments) {
          previousObjectSegmentInfos.set(
            currentObjNames.get(objInfo.name) + segInfo.name,
            {
              include: segInfo.include,
              allocatedVaddr: segInfo.allocatedVaddr,
            }
          );
        }
      }
    }

    for (const objInfo of updatedObjectInfos) {
      for (const segInfo of objInfo.segments) {
        const prevInfo = previousObjectSegmentInfos.get(
          objInfo.name + segInfo.name
        );
        if (prevInfo) {
          segInfo.allocatedVaddr = prevInfo.allocatedVaddr;
          segInfo.include = prevInfo.include;
        }
      }
    }

    patchInfo.objectInfos = updatedObjectInfos;
    patchInfo.objectInfosValid = true;

    assignSegmentColors(patchInfo);
  }

  function validVaddr(vaddr) {
    return vaddr || 0 === vaddr;
  }

  function updateSummary() {
    patchInfo.symbolRefMap = buildSymbolRefMap(patchInfo);

    const newOverview = {};
    newOverview.totalBytes = 0;
    newOverview.nSegments = 0;
    for (const obj of patchInfo.objectInfos) {
      for (const seg of obj.segments) {
        if (seg.include) {
          newOverview.totalBytes += seg.size;
          newOverview.nSegments++;
        }
      }
    }

    newOverview.unresolvedSyms = new Set();
    if (patchInfo.symbolRefMap) {
      for (const symName of patchInfo.symbolRefMap.allSyms) {
        if (patchInfo.symbolRefMap[symName].providedBy.length === 0) {
          newOverview.unresolvedSyms.add(symName);
        }
      }
    }

    newOverview.unallocatedSegments = [];
    for (const obj of patchInfo.objectInfos) {
      for (const seg of obj.segments) {
        if (seg.include && !validVaddr(seg.allocatedVaddr)) {
          newOverview.unallocatedSegments.push([obj.name, seg.name]);
        }
      }
    }

    newOverview.nSources = patchInfo.sourceInfos.length;

    overview = newOverview;
  }

  async function updatePatchPlacement() {
    if (addLogBreak) {
      addLogBreak();
    }
    // Rebuild BOM, fetch updated objectInfos
    let updatedObjectInfos = await fetchObjectInfos(
      patchInfo.name,
      patchInfo.userInputs.toolchain,
      patchInfo.userInputs.toolchainConfig
    );
    // If that succeeds
    importObjectInfos(updatedObjectInfos);
    updateSummary();
  }

  async function updateSymbolDefines() {
    if (!patchInfo.objectInfosValid) {
      // rebuilds BOM if it is outdated
      // must be build to know what symbols it needs and grab those from target
      await updatePatchPlacement();
    } else {
      if (addLogBreak) {
        addLogBreak();
      }
    }

    patchInfo.targetInfo = await fetchTargetInfo(patchInfo.name);

    patchInfo.targetInfoValid = true;
    updateSummary();
  }

  function _devResetAll() {
    patchInfo = fakePatchInfo();
    updatePatchPlacement().then(() => {
      updateSymbolDefines().then(updateSummary);
    });
  }

  function goBack() {
    fetch(
      `${$settings.backendUrl}/${$selectedResource.resource_id}/patch_wizard/save_current_patch`,
      {
        method: "POST",
        headers: {
          "Content-Type": "application/json",
        },
        body: JSON.stringify(patchInfo),
      }
    ).then(async (r) => {
      if (!r.ok) {
        throw Error(JSON.stringify(await r.json(), undefined, 2));
      }
    });
    popViewCrumb();
  }

  async function populatePatchInfo() {
    const patches = await fetchPatchesInProgress();

    if (patches.length === 1) {
      patchInfo = patches[0];
      updateSummary();
    } else {
      const r = await fetch(
        `${$settings.backendUrl}/${
          $selectedResource.resource_id
        }/patch_wizard/start_new_patch?patch_name=${"Example_Patch"}`,
        {
          method: "POST",
          headers: {
            "Content-Type": "application/json",
          },
          body: "",
        }
      );
      if (!r.ok) {
        throw Error(JSON.stringify(await r.json(), undefined, 2));
      } else {
        patchInfo = await r.json();
      }
    }
  }

  let patchInfoPromise = populatePatchInfo();
</script>

<Split>
  <Split slot="first" vertical="{true}" percentOfFirstSplit="{66.666}">
    <Pane slot="first">
      <div class="summary-info-header-bar">
        OVERVIEW <button class="refresh-button" on:click="{updateSummary}"
          >Refresh</button
        >
      </div>
      {#await patchInfoPromise}
        <Loading />
      {:then _}
        <div class="summary-body">
          <SummaryWidget
            title="Step 1. Toolchain & Patch Source"
            markError="{!(
              patchInfo.userInputs.toolchain && overview.nSources > 0
            )}"
            valid="{null}"
            updateFunction="{() => {}}"
            errorReason=""
          >
            {#if patchInfo.userInputs.toolchain && overview.nSources}
              <p>
                Using {patchInfo.userInputs.toolchain.split(".").pop()} to build
                patch from
                {overview.nSources} source code files.
              </p>
            {:else if overview.nSources}
              <p class="warning">No toolchain selected</p>
              <p>to build {overview.nSources} source code files.</p>
            {:else if patchInfo.userInputs.toolchain}
              <p>Using {patchInfo.userInputs.toolchain.split(".").pop()}</p>
              <p class="warning">
                but no source code files to build patch from!
              </p>
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
            markError="{overview.nSegments === 0 ||
              overview.unallocatedSegments.length > 0}"
            valid="{patchInfo.objectInfosValid}"
            updateFunction="{updatePatchPlacement}"
            errorReason="Must allocate segments!"
          >
            <p>Something about free space</p>
            {#if overview.nSegments}
              <p>
                {overview.nSegments} segment{overview.nSegments > 1 ? "s" : ""} totaling
                0x{overview.totalBytes.toString(16)} bytes will be extracted from
                the compiled sources and injected into the target binary at unique
                addresses.
              </p>
            {:else}
              <p class="warning">No segments chosen for injection!</p>
            {/if}
            {#if overview.unallocatedSegments.length > 0}
              <p class="warning">
                {overview.unallocatedSegments.length} segment(s) still need to be
                allocated:
              </p>
              {#each overview.unallocatedSegments as [objName, segName]}
                <p>{objName}{segName}</p>
              {/each}
            {/if}
            <br />
            <Button on:click="{() => (subMenu = null)}"
              >Create Free Space</Button
            >
            <Button on:click="{() => (subMenu = ObjectMappingView)}"
              >Configure Patch Placement</Button
            >
          </SummaryWidget>
          <SummaryWidget
            title="Step 3. Symbol Definitions"
            markError="{overview.unresolvedSyms.size > 0}"
            valid="{patchInfo.targetInfoValid}"
            updateFunction="{updateSymbolDefines}"
            errorReason="There are unresolved symbols!"
          >
            {#if patchInfo.symbolRefMap}
              <p>
                Target binary provides {patchInfo.targetInfo.symbols.length} symbols:
              </p>

              {#each patchInfo.targetInfo.symbols as sym}
                <PatchSymbol
                  symbolName="{sym}"
                  symbolRefMap="{patchInfo.symbolRefMap}"
                />
              {/each}

              {#if patchInfo.userInputs.symbols}
                <p>
                  You are providing {patchInfo.userInputs.symbols.length} symbol(s).
                </p>
              {/if}

              {#if overview.unresolvedSyms.size > 0}
                {#if overview.unresolvedSyms.size === 1}
                  <p class="warning">There as an unresolved symbol!</p>
                {:else}
                  <p class="warning">
                    There are {overview.unresolvedSyms.size} unresolved symbols!
                  </p>
                {/if}
                {#each Array.from(overview.unresolvedSyms) as sym}
                  <PatchSymbol
                    symbolName="{sym}"
                    symbolRefMap="{patchInfo.symbolRefMap}"
                  />
                {/each}
                <p>
                  These symbols are referenced by the patch code, but not
                  defined in the patch code or the binary.
                </p>
              {:else}
                <p>There are no unresolved symbols.</p>
              {/if}
            {/if}
            <br />
            <Button on:click="{() => (subMenu = SymbolView)}"
              >Define Symbols Manually</Button
            >
          </SummaryWidget>
        </div>
      {/await}

      <div class="nav-bar">
        <Button on:click="{goBack}">Back</Button>
        <Button on:click="{() => doPatch(patchInfo)}">Inject</Button>
        <Button on:click="{_devResetAll}">(Development) Reset)</Button>
      </div>
    </Pane>
    <Pane slot="second" paddingVertical="{'1em'}">
      {#await patchInfoPromise}
        <Loading />
      {:then _}
        <PatchMakerLogsView
          patchInfo="{patchInfo}"
          bind:addLogBreak="{addLogBreak}"
        />
      {/await}
    </Pane>
  </Split>
  <Pane slot="second">
    {#if subMenu}
      <svelte:component
        this="{subMenu}"
        bind:subMenu="{subMenu}"
        bind:patchInfo="{patchInfo}"
        refreshOverviewCallback="{updateSummary}"
      />
    {/if}
  </Pane>
</Split>
