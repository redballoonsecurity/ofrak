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
    overflow: hidden;
  }

  .inner {
    overflow: hidden;
    flex-grow: 1;
  }
</style>

<script>
  export let paddingVertical = "0",
    paddingHorizontal = "0";
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
