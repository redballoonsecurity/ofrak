<style>
  .box {
  }

  .new-sym-box {
    display: inline-flex;
    align-items: center;
    height: fit-content;
  }

  label {
    background-color: var(--main-bg-color);
    color: var(--main-fg-color);
    max-width: 10em;
  }

  input {
    background-color: var(--main-bg-color);
    color: var(--main-fg-color);
    max-width: 10em;
  }
</style>

<script>
  import UserInputSymbol from "./UserInputSymbol.svelte";
  import Button from "../utils/Button.svelte";
  import PatchSymbol from "./PatchSymbol.svelte";
  import Icon from "../utils/Icon.svelte";

  export let patchInfo, refreshOverviewCallback;

  let newName, newVaddr;
  let undefinedSymsCollapse = false;

  let unresolvedSyms = new Set();

  function pushNewSymbol() {
    if (!newName || !(newVaddr || newVaddr === 0x0)) {
      return;
    }
    patchInfo.userInputs.symbols = [
      [newName, newVaddr],
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

Define symbols which are required by the patch code and not provided by the
target binary.

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
    <label>
      <input placeholder="Symbol name" bind:value="{newName}" />
    </label>

    <label>
      <input placeholder="Address" bind:value="{newVaddr}" />
    </label>

    <Button on:click="{pushNewSymbol}"><Icon url="/icons/plus.svg" /></Button>
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
