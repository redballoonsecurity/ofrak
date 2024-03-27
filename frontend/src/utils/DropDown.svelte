<style>
  .option:hover {
    backdrop-filter: invert(20%)
  }

  .menu {
    background-color: var(--main-bg-color);
    border: solid var(--main-fg-color) 1px;
  }
</style>

<script>
  export let options, selection;
  let optionElements = {};
</script>

<div class="menu">
  {#each options as option}
    <!-- svelte-ignore a11y-click-events-have-key-events -->
    <!-- svelte-ignore a11y-no-static-element-interactions -->
    <div
      class="option"
      bind:this="{optionElements[option]}"
      on:click="{(e) => {
        selection = option;
      }}"
    >
      {option}
    </div>
  {/each}
</div>
