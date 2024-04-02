<style>
  .option:hover {
    backdrop-filter: invert(20%);
  }

  .option:focus {
    backdrop-filter: invert(20%);
  }

  .menu {
    background-color: var(--main-bg-color);
    border: 1px solid var(--main-fg-color);
  }
</style>

<script>
  export let options, selection;
  let optionElements = {};
  let focused;

  document.onkeydown = function (e) {
    if (e.key == "Enter") {
      selection = focused;
    }
  };
</script>

<div class="menu">
  {#each options as option}
    <!-- svelte-ignore a11y-click-events-have-key-events -->
    <!-- svelte-ignore a11y-no-static-element-interactions -->
    <!-- svelte-ignore a11y-no-noninteractive-tabindex -->
    <div
      class="option"
      tabindex="0"
      bind:this="{optionElements[option]}"
      on:click="{(e) => {
        selection = option;
      }}"
      on:focus="{(e) => {
        focused = option;
      }}"
    >
      {option}
    </div>
  {/each}
</div>
