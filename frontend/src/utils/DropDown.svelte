<style>
  .option:hover {
    background-color: hsl(
      from var(--main-bg-color) h s calc(l + 0.8 * (0.5 - l))
    );
  }

  .option {
    border: solid hsl(from var(--main-fg-color) h s calc(l + 0.8 * (0.5 - l)))
      1px;
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
