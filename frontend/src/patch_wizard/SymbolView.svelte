<style>
  .new-sym-box {
    display: inline;
  }

  label {
    background-color: var(--main-bg-color);
    color: var(--main-fg-color);
    max-width: 10em;
  }
</style>

<script>
  import UserInputSymbol from "./UserInputSymbol.svelte";
  import Button from "../utils/Button.svelte";

  export let patchInfo, refreshOverviewCallback;

  let symbols = Object.entries(patchInfo.userInputs.symbols).filter(([k, v]) =>
    patchInfo.userInputs.symbols.hasOwnProperty(k)
  );

  let newName, newVaddr;
</script>

We define symbols manually here

{#each symbols as [name, vaddr]}
  <UserInputSymbol name="{name}" vaddr="{vaddr}" />
{/each}

<div class="new-sym-box">
  <label>
    <input placeholder="Symbol name" bind:value="{newName}" />
  </label>

  <label>
    <input placeholder="Address" bind:value="{newVaddr}" />
  </label>

  <Button>Add new</Button>
</div>
