<style>
  .outlined-box {
    border: thin solid;
    padding: 1em;
    margin-bottom: 1.5em;
  }
  .alloc-box {
    display: inline-flex;
    height: fit-content;
    width: 100%;
  }

  .seg-box {
    width: 50%;
    min-height: 100%;
  }

  .freespace-box {
    width: 50%;
    min-height: 100%;
  }

  .invalid {
    opacity: 50%;
  }

  .complex-block {
    display: flex;
  }

  .cb-info {
    margin-left: 1em;
  }

  .cb-list {
    max-height: 10em;
    overflow-y: scroll;
  }

  .extension-tech-box {
    border: thin dotted;
    margin-top: 1em;
    padding: 0.5em;
  }

  .warning {
    text-decoration-line: underline;
    text-decoration-color: red;
  }
</style>

<script>
  import Button from "../utils/Button.svelte";

  import { selectedResource, settings } from "../stores";
  import Checkbox from "../utils/Checkbox.svelte";
  import SegmentWidget from "./SegmentWidget.svelte";
  import LoadingText from "../utils/LoadingText.svelte";

  export let patchInfo, refreshOverviewCallback;

  let unallocatedSegments = [];

  let freeSpacePromise = getFreeSpace();

  let segFilterR = false,
    segFilterW = false,
    segFilterX = false;
  let unallocatedOnly = false;
  let filteredUnallocatedSegments = [];
  let freeFilterR = false,
    freeFilterW = false,
    freeFilterX = false;
  let filteredFreeSpacePromise = Promise.resolve([]);

  if (patchInfo.extensionMethodStatus === undefined) {
    patchInfo.extensionMethodStatus = {
      note: { valid: true, status: null },
      load_align: { valid: true, status: null },
    };
  }

  let complexBlocksToFree = {};

  const canExtend = $selectedResource.tags.includes("ofrak.core.elf.model.Elf");

  async function getFreeSpace() {
    await $selectedResource.run_component("FreeSpaceAnalyzer", "", [
      "ofrak.model.component_model.ComponentConfig",
      {},
    ]);
    return $selectedResource.attributes[
      "ofrak.model._auto_attributes.AttributesType[Allocatable]"
    ].free_space_ranges;
  }

  async function extendElf(method) {
    // await $selectedResource.run_component("ElfLoadAlignmentModifier");
    fetch(
      `${$settings.backendUrl}/patch_wizard/extend_elf?patch_name=${patchInfo.name}&method=${method}`,
      {
        method: "POST",
      }
    ).then(async (r) => {
      if (!r.ok) {
        if (r.status === 520) {
          patchInfo.extensionMethodStatus[method].valid = false;
        } else {
          throw Error(JSON.stringify(await r.json(), undefined, 2));
        }
      } else {
        freeSpacePromise = getFreeSpace();
        if (method === "note") {
          patchInfo.extensionMethodStatus["load_align"] = {
            valid: false,
            status:
              "After introducing a new segment with NOTE-replacing, alignment recovery would give uncertain results.",
          };
        }
      }
      patchInfo.extensionMethodStatus[method].status = await r.text();
    });
  }

  async function getComplexBlocks() {
    return fetch(
      `${$settings.backendUrl}/patch_wizard/get_complex_blocks?patch_name=${patchInfo.name}`,
      {
        method: "POST",
      }
    ).then(async (r) => {
      if (!r.ok) {
        throw Error(JSON.stringify(await r.json(), undefined, 2));
      } else {
        return await r.json();
      }
    });
  }

  function totalSelectedComplexBlockSize(_complexBlocksToFree, complexBlocks) {
    const complexBlockSizeMap = Object.fromEntries(
      complexBlocks.map((cbObject) => [cbObject.id, cbObject.size])
    );
    return Object.entries(_complexBlocksToFree)
      .filter(([id, _]) => _complexBlocksToFree.hasOwnProperty(id)) // Filter generic object stuff
      .filter(([_, selected]) => selected) // Get IDs of selected CBs
      .map(([id, _]) => complexBlockSizeMap[id]) // Get sizes of selected CBs
      .reduce((sum, size) => sum + size, 0); // Sum sizes of selected CBs
  }

  async function freeComplexBlocks() {
    const idsToFree = Object.entries(complexBlocksToFree)
      .filter(([id, _]) => complexBlocksToFree.hasOwnProperty(id)) // Filter generic object stuff
      .filter(([_, selected]) => selected) // Get IDs of selected CBs
      .map(([id, _]) => id); // Only need the IDs

    await fetch(
      `${$settings.backendUrl}/patch_wizard/free_complex_blocks?patch_name=${patchInfo.name}`,
      {
        method: "POST",
        body: JSON.stringify(idsToFree),
      }
    ).then(async (r) => {
      if (!r.ok) {
        throw Error(JSON.stringify(await r.json(), undefined, 2));
      }
      freeSpacePromise = getFreeSpace();
      complexBlocksPromise = getComplexBlocks();
    });
  }

  function permsMatch(perms, r, w, x) {
    // Permissions "match" if either:
    // 1. No specific permissions have been checked
    // 2. The permissions checked EXACTLY match the passed perms
    return (
      (!r && !w && !x) ||
      (perms.includes("r") === r &&
        perms.includes("w") === w &&
        perms.includes("x") === x)
    );
  }

  function permsToString(r, w, x) {
    return (r ? "R" : "") + (w ? "W" : "") + (x ? "X" : "");
  }

  function totalSize(segInfos) {
    return segInfos.reduce((sum, segInfo) => sum + segInfo.size, 0);
  }

  let complexBlocksPromise = getComplexBlocks();

  // Update overall list of unallocated segments
  $: if (patchInfo.objectInfos) {
    unallocatedSegments = patchInfo.objectInfos
      .map((objInfo) => objInfo.segments) // Extract the segments
      .flat() // Convert from array of arrays to flat array of all segments
      .filter((segInfo) => segInfo.include) // Only segments included in patch
      .filter((segInfo) => typeof segInfo.allocatedVaddr !== "number"); // Only unallocated segs
  }

  // Update filtered list of unallocated segments matching selected segment permissions
  $: if (patchInfo.objectInfos) {
    filteredUnallocatedSegments = patchInfo.objectInfos
      .map((objInfo) => objInfo.segments) // Extract the segments
      .flat() // Convert from array of arrays to flat array of all segments
      .filter((segInfo) => segInfo.include) // Only segments included in patch
      .filter(
        (segInfo) =>
          !unallocatedOnly || typeof segInfo.allocatedVaddr !== "number"
      ) // Only unallocated segs?
      .filter((segInfo) =>
        permsMatch(segInfo.permissions, segFilterR, segFilterW, segFilterX)
      );
  }

  // Update the list of free space blocks matching selected free space permissions
  $: if (freeSpacePromise) {
    filteredFreeSpacePromise = freeSpacePromise.then((fs) => {
      const filteredFreeBlocks = fs
        .filter(([perms, ranges]) =>
          permsMatch(
            perms.split(".").at(-1).toLowerCase(),
            freeFilterR,
            freeFilterW,
            freeFilterX
          )
        ) // Only blocks matching the selected permissions
        .map(([perms, ranges]) => ranges) // Only need the free blocks
        .flat(); // Convert from array of arrays to flat array of free block ranges
      filteredFreeBlocks.sort(
        ([start1, end1], [start2, end2]) => end2 - start2 - (end1 - start1)
      );
      return filteredFreeBlocks;
    });
  }
</script>

{#if unallocatedSegments.length > 0}
  <p class="warning">
    {unallocatedSegments.length} segment(s) totaling 0x{totalSize(
      unallocatedSegments
    ).toString(16)} bytes still need to be allocated.
  </p>
{:else if patchInfo?.objectInfos}
  <p>
    No unallocated segments (out of {patchInfo.objectInfos
      .map((objInfo) => objInfo.segments)
      .flat()
      .filter((seg) => seg.include).length} segments included).
  </p>
{:else}
  <p>No segments.</p>
{/if}
<div class="alloc-box">
  <div class="seg-box outlined-box">
    <div class="perms-select">
      <h3>Segments to allocate:</h3>
      <Checkbox bind:value="{segFilterR}" checked="{false}">R</Checkbox>
      <Checkbox bind:value="{segFilterW}" checked="{false}">W</Checkbox>
      <Checkbox bind:value="{segFilterX}" checked="{false}">X</Checkbox>

      <Checkbox bind:value="{unallocatedOnly}" checked="{false}"
        >Unallocated Only</Checkbox
      >
    </div>

    <p>
      Total {unallocatedOnly ? "unallocated" : ""}
      {permsToString(segFilterR, segFilterW, segFilterX)} segment size: 0x{totalSize(
        filteredUnallocatedSegments
      ).toString(16)}
    </p>

    {#each filteredUnallocatedSegments as segInfo}
      <SegmentWidget
        segmentInfo="{segInfo}"
        refreshOverviewCallback="{refreshOverviewCallback}"
        lockInclude="{true}"
      />
    {/each}
  </div>

  <div class="freespace-box outlined-box">
    <div class="perms-select">
      <h3>Free Space to allocate:</h3>
      <Checkbox bind:value="{freeFilterR}" checked="{false}">R</Checkbox>
      <Checkbox bind:value="{freeFilterW}" checked="{false}">W</Checkbox>
      <Checkbox bind:value="{freeFilterX}" checked="{false}">X</Checkbox>
    </div>

    {#await freeSpacePromise}
      <p>Fetching free space...</p>
    {:then freeSpace}
      {#await filteredFreeSpacePromise}
        <p>Processing free space...</p>
      {:then filteredFreeSpace}
        <p>
          {filteredFreeSpace.length} matching blocks of {permsToString(
            freeFilterR,
            freeFilterW,
            freeFilterX
          )} free space (out of {freeSpace.map(([_, ranges]) => ranges).flat()
            .length} total ranges with {freeSpace.length} unique permission spec{freeSpace.length >
          1
            ? "s"
            : ""}).
        </p>
        {#each filteredFreeSpace as [blockStart, blockEnd]}
          <p>
            [0x{blockStart.toString(16)}-0x{blockEnd.toString(16)} (0x{(
              blockEnd - blockStart
            ).toString(16)} bytes)]
          </p>
        {/each}
        <p>
          Total {permsToString(freeFilterR, freeFilterW, freeFilterX)} free space:
          0x{filteredFreeSpace
            .reduce((sum, [start, end]) => sum + end - start, 0)
            .toString(16)}
        </p>
      {/await}
    {/await}
  </div>
</div>

<div class="extension-box outlined-box" class:invalid="{!canExtend}">
  <h3>Create Free Space: Extend Binary (ELF Only)</h3>
  <div class="extension-tech-box">
    <h4>Recover Unused Alignment</h4>
    <p>
      Reclaim unused alignment bytes between adjacent PT_LOAD segment in an ELF
      and tag them as free space. Alignment bytes often exist between PT_LOAD
      sections in ELF binaries. These alignment bytes are added to the preceding
      PT_LOAD segment. This is the least invasive ELF extension technique.
    </p>

    <Button
      on:click="{() => extendElf('load_align')}"
      disabled="{!canExtend ||
        !patchInfo.extensionMethodStatus.load_align.valid}">Apply</Button
    >
    {#if patchInfo.extensionMethodStatus.load_align.status}
      {#if patchInfo.extensionMethodStatus.load_align.valid}
        <p>Success! {patchInfo.extensionMethodStatus.load_align.status}</p>
      {:else}
        <p class="warning">
          {patchInfo.extensionMethodStatus.load_align.status}
        </p>
      {/if}
    {/if}
  </div>
  <div class="extension-tech-box">
    <h4>Replace NOTE Segment</h4>
    <p>
      If the ELF has a .NOTE segment, we can replace the .NOTE header with a
      .LOAD header pointing to some new space we weill add at the end. Adds
      0x1000 bytes by default. WARNING: Will require the ELF to be re-analyzed
      and unpacked.
    </p>
    <Button
      on:click="{() => extendElf('note')}"
      disabled="{!canExtend || !patchInfo.extensionMethodStatus.note.valid}"
      >Apply</Button
    >
    {#if patchInfo.extensionMethodStatus.note.status}
      {#if patchInfo.extensionMethodStatus.note.valid}
        <p>Success! {patchInfo.extensionMethodStatus.note.status}</p>
      {:else}
        <p class="warning">{patchInfo.extensionMethodStatus.note.status}</p>
      {/if}
    {/if}
  </div>
</div>

<div class="functions-box outlined-box">
  <h3>Create Free Space: Overwrite Existing Functions</h3>

  {#await complexBlocksPromise}
    <LoadingText />
  {:then complexBlocks}
    <div class="cb-list">
      {#each complexBlocks as cbObject}
        <div class="complex-block">
          <Checkbox
            checked="{false}"
            bind:value="{complexBlocksToFree[cbObject.id]}"
          />
          <p class="cb-info">
            {cbObject.name} (0x{cbObject.vaddr.toString(16)}-0x{(
              cbObject.vaddr + cbObject.size
            ).toString(16)})
          </p>
        </div>
      {/each}
    </div>

    <p>
      0x{totalSelectedComplexBlockSize(
        complexBlocksToFree,
        complexBlocks
      ).toString(16)} bytes of RX space will be created.
    </p>

    <Button on:click="{freeComplexBlocks}">Free</Button>
  {/await}
</div>
