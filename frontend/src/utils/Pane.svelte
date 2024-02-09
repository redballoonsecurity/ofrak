<style>
  * {
    box-sizing: border-box;
  }

  .outer {
    height: 100%;
    background-color: var(--main-bg-color);
    display: flex;
    flex-flow: row;
    justify-content: space-between;
    align-items: stretch;
  }

  .inner {
    overflow: auto;
    flex-grow: 1;
  }

  .minimap-container {
    background: var(--main-bg-color);
    display: flex;
    z-index: 1;
  }

  .minimap {
    width: 64px;
    max-width: 64px;
    display: flex;
    flex-flow: column;
    justify-content: space-between;
    align-items: center;
  }
</style>

<script>
  import { onMount } from "svelte";

  export let paddingVertical = "3em",
    paddingHorizontal = "3em";
  let inner;
</script>

<div class="outer">
  <div
    bind:this="{inner}"
    class="inner"
    style:margin-top="{paddingVertical}"
    style:margin-bottom="{paddingVertical}"
    style:margin-left="{paddingHorizontal}"
    style:margin-right="{paddingHorizontal}"
    style:height="{`calc(100% - ${paddingVertical} * 2)`}"
  >
    <slot />
  </div>
</div>
