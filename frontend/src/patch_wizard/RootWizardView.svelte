<script>
  import Split from "../utils/Split.svelte";
  import Pane from "../utils/Pane.svelte";
  import Button from "../utils/Button.svelte";

  import {
    popViewCrumb,
    selectedResource,
    settings,
    viewCrumbs,
  } from "../stores";
  import { fakePatchInfo } from "./dev_consts";
  import SourceMenuView from "./SourceMenuView.svelte";
  import SummaryView from "./SummaryView.svelte";
  import ObjectMappingView from "./ObjectMappingView.svelte";
  import ToolchainSetupView from "./ToolchainSetupView.svelte";

  let subMenu = undefined;

  let patchInfo = fakePatchInfo();

  function freshPatchInfo() {
    patchInfo = {
      name: "Example Patch",
      sourceInfos: [],
      objectInfosValid: false,
      objectInfos: [],
      targetInfo: {},
      targetInfoValid: false,
      userInputs: {},
      symbolRefMap: null,
    };
  }

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

    return refMap;
  }

  function updateObjectInfos(patchInfo, updatedObjectInfos) {
    // May mutate updatedObjectInfos

    // Keep track of when source files were renamed, but their object placements should still be preserved
    const currentObjNames = new Map();
    for (const sourceInfo of patchInfo.sourceInfos) {
      if (sourceInfo.originalName) {
        currentObjNames.add(sourceInfo.originalName, sourceInfo.name);
      } else {
        currentObjNames.add(sourceInfo.name, sourceInfo.name);
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
            { include: segInfo.include, allocatedVaddr: segInfo.allocatedVaddr }
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
  }

  assignSegmentColors(patchInfo);
  patchInfo.symbolRefMap = buildSymbolRefMap(patchInfo);
</script>

<Split>
  <Split slot="first" vertical="{true}" percentOfFirstSplit="{66.666}">
    <Pane slot="first">
      <SummaryView patchInfo="{patchInfo}" bind:subMenu="{subMenu}" />
      <Button on:click="{popViewCrumb}">Back</Button>
      <Button>Inject</Button>
      <Button
        on:click="{() => {
          patchInfo = fakePatchInfo();
        }}">(Development) Reset)</Button
      >
    </Pane>
    <Pane slot="second" paddingVertical="{'1em'}">
      TO-DO: Patchmaker error logs.
    </Pane>
  </Split>
  <Pane slot="second">
    {#if subMenu}
      <svelte:component
        this="{subMenu}"
        bind:subMenu="{subMenu}"
        bind:patchInfo="{patchInfo}"
      />
    {/if}
  </Pane>
</Split>
