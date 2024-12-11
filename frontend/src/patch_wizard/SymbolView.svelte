<style>
  .box {
    width: calc(100% - 2px);
  }

  .undefined-syms-box {
    margin: 1em;
    width: 100%;
  }

  .new-sym-box {
    display: inline-flex;
    align-items: center;
    height: fit-content;
    border: thin solid;
    width: 100%;
  }

  label {
    background-color: var(--main-bg-color);
    color: var(--main-fg-color);
    width: 40%;
    margin: 0.5em;
  }

  input {
    background-color: var(--main-bg-color);
    color: var(--main-fg-color);
    width: 100%;
  }

  .name-label {
    margin-right: auto;
  }

  .vaddr-label {
    margin-left: auto;
    margin-right: auto;
  }
</style>

<script>
  import UserInputSymbol from "./UserInputSymbol.svelte";
  import Button from "../utils/Button.svelte";
  import PatchSymbol from "./PatchSymbol.svelte";
  import Icon from "../utils/Icon.svelte";

  export let patchInfo, refreshOverviewCallback;

  let newName = null,
    newVaddr = null;
  let undefinedSymsCollapse = false;

  let unresolvedSyms = new Set();

  function pushNewSymbol() {
    if (!newName || newVaddr === null) {
      return;
    }
    let parsedVaddr;
    if (newVaddr.startsWith("0x")) {
      parsedVaddr = parseInt(newVaddr, 16);
    } else {
      parsedVaddr = parseInt(newVaddr);
    }
    // newVaddr is a string you buffoon, it needs to be an int
    patchInfo.userInputs.symbols = [
      [newName, parsedVaddr],
      ...patchInfo.userInputs.symbols,
    ];
    newName = null;
    newVaddr = null;
    refreshOverviewCallback();
  }

  function deleteSym(idx) {
    patchInfo.userInputs.symbols = patchInfo.userInputs.symbols.toSpliced(
      idx,
      1
    );
    refreshOverviewCallback();
  }

  $: {
    if (patchInfo.symbolRefMap) {
      unresolvedSyms = new Set();
      for (const symName of patchInfo.symbolRefMap.allSyms) {
        if (patchInfo.symbolRefMap[symName].providedBy.length === 0) {
          unresolvedSyms.add(symName);
        }
      }
    }
  }
</script>

<div class="description">
  Define symbols which are required by the patch code and not provided by the
  target binary.
</div>

<div class="undefined-syms-box">
  <button
    on:click="{() => {
      undefinedSymsCollapse = !undefinedSymsCollapse;
    }}"
  >
    {#if undefinedSymsCollapse}
      [+]
    {:else}
      [-]
    {/if}
  </button>
  {#if unresolvedSyms}
    There are {unresolvedSyms.size} unresolved symbols.
  {:else}
    There are no unresolved symbols.
  {/if}
  {#if !undefinedSymsCollapse}
    <div class="undefined-syms-collapse-box">
      {#each Array.from(unresolvedSyms) as sym}
        <PatchSymbol
          symbolName="{sym}"
          symbolRefMap="{patchInfo.symbolRefMap}"
        />
      {/each}
    </div>
  {/if}
</div>

<div class="box">
  <div class="new-sym-box">
    <label class="name-label">
      <input placeholder="Symbol name" bind:value="{newName}" />
    </label>

    <label class="vaddr-label">
      <input placeholder="Address" bind:value="{newVaddr}" />
    </label>

    <Button on:click="{pushNewSymbol}" --button-margin="0.5em 0.5em 0.5em auto"
      ><Icon url="/icons/plus.svg" /></Button
    >
  </div>

  {#each patchInfo.userInputs.symbols as [name, vaddr], idx}
    <UserInputSymbol
      bind:name="{name}"
      bind:vaddr="{vaddr}"
      deleteSym="{() => {
        deleteSym(idx);
      }}"
    />
  {/each}
</div>
