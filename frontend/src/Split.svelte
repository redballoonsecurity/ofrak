<style>
  .container {
    display: flex;
    flex-wrap: nowrap;
    justify-content: space-evenly;
    align-items: stretch;
    height: 100%;
    background: var(--main-bg-color);

    /* Default to horizontal split */
    flex-direction: row;
  }

  .vertical {
    flex-direction: column;
  }

  #first,
  #second {
    overflow: hidden;
  }

  #first {
    /* Default to horizontal split */
    border-right: 2px dashed var(--main-fg-color);
  }

  :global(.gutter-horizontal) {
    position: relative;
    left: calc(-20px / 2);
    cursor: col-resize;
  }

  :global(.gutter-vertical) {
    position: relative;
    top: calc(-20px / 2);
    cursor: row-resize;
  }
</style>

<script>
  import { onMount } from "svelte";

  import Split from "split.js";

  export let vertical = false,
    percentOfFirstSplit = 50;
  let first, second;

  onMount(() => {
    Split([first, second], {
      sizes: [percentOfFirstSplit, 100 - percentOfFirstSplit],
      direction: vertical ? "vertical" : "horizontal",
      gutterSize: 20,
      gutterAlign: "center",
    });
  });
</script>

<div class="container" class:vertical>
  <div
    id="first"
    style:border="{vertical ? "none" : ""}"
    style:border-bottom="{vertical ? "2px dashed var(--main-fg-color)" : ""}"
    bind:this="{first}"
  >
    <slot name="first" />
  </div>
  <div id="second" bind:this="{second}">
    <slot name="second" />
  </div>
</div>
