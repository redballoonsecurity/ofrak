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
    paddingHorizontal = "3em",
    scrollY = undefined,
    displayMinimap = false;

  let inner;
  function updateScrollTop(scrollPercent) {
    if (inner !== undefined) {
      inner.scrollTop =
        scrollPercent *
        (inner.scrollHeight - inner.clientTop - inner.clientHeight);
    }
  }
  $: if (scrollY !== undefined && $scrollY !== undefined) {
    refreshHeight();
    updateScrollTop($scrollY.top);
  }

  function refreshHeight() {
    if (
      inner !== undefined &&
      scrollY !== undefined &&
      $scrollY !== undefined
    ) {
      $scrollY.viewHeightPixels = inner.clientHeight;
      $scrollY.viewHeight =
        inner.clientHeight / (inner.scrollHeight - inner.clientTop);
    }
  }
  onMount(refreshHeight);
</script>

<svelte:window on:resize="{refreshHeight}" />

<div class="outer">
  {#if scrollY !== undefined}
    <div
      bind:this="{inner}"
      class="inner"
      style:margin-top="{paddingVertical}"
      style:margin-bottom="{paddingVertical}"
      style:margin-left="{paddingHorizontal}"
      style:margin-right="{paddingHorizontal}"
      style:height="{`calc(100% - ${paddingVertical} * 2)`}"
      on:scroll="{(e) => {
        $scrollY.top =
          // FIXME: Subtracting clientHeight allows the user to scroll a little
          // bit past the bottom of the hex, but right now this is the only way
          // to guarantee the bottom of the data is visible
          e.target.scrollTop /
          (e.target.scrollHeight - e.target.clientTop - e.target.clientHeight);
        $scrollY.viewHeightPixels = inner.clientHeight;
        $scrollY.viewHeight =
          e.target.clientHeight / (e.target.scrollHeight - e.target.clientTop);
        $scrollY = $scrollY;
      }}"
    >
      <slot />
    </div>
  {:else}
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
  {/if}

  {#if displayMinimap}
    <div class="minimap-container">
      <div
        class="minimap"
        style:margin-top="{paddingVertical}"
        style:margin-bottom="{!!window.chrome
          ? `calc(${paddingVertical} * 2)`
          : paddingVertical}"
        style:margin-right="{paddingHorizontal}"
      >
        <slot name="minimap" />
      </div>
    </div>
  {/if}
</div>
