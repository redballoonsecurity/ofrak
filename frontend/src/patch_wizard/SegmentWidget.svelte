<style>
  .box {
    border: thin solid;
    background-color: var(--own-bg-color);
    color: var(--own-txt-color);
    margin-bottom: 1ch;
    width: 100%;
  }

  .warning {
    text-decoration-line: underline;
    text-decoration-color: red;
  }

  .header-bar {
    border: thin solid;
    width: 100%;
    align-items: center;
    display: flex;
  }

  .seg-vaddr-input {
    background-color: var(--own-bg-color);
    color: var(--own-txt-color);
    max-width: 10em;
  }

  .details-box {
    padding-left: 1ch;
    padding-right: 1ch;
  }
</style>

<script>
  import Checkbox from "../utils/Checkbox.svelte";
  import { settings } from "../stores";

  export let segmentInfo, refreshOverviewCallback;

  function validVaddr(vaddr) {
    return vaddr || 0 === vaddr;
  }

  let placeholderVaddr, inputVaddr;
  let prevInclude = segmentInfo.include;

  function updatePlaceholderVaddr() {
    if (segmentInfo.allocatedVaddr || segmentInfo.allocatedVaddr === 0) {
      placeholderVaddr = "0x" + segmentInfo.allocatedVaddr.toString(16);
    } else {
      placeholderVaddr = "Needs allocation!";
    }
  }

  updatePlaceholderVaddr();

  let backgroundColor, textColor;

  $: {
    if (inputVaddr || inputVaddr === 0) {
      if (inputVaddr.length === 0) {
        segmentInfo.allocatedVaddr = undefined;
      }
      const parsed = parseInt(inputVaddr, 16);
      if (parsed >= 0) {
        // filters out NaN
        segmentInfo.allocatedVaddr = parsed;
      }
    }
    refreshOverviewCallback;
  }

  $: {
    if (segmentInfo.include) {
      backgroundColor = segmentInfo.color;
      textColor = $settings.background;
    } else {
      backgroundColor = $settings.background;
      textColor = $settings.foreground;
    }

    if (segmentInfo.include !== prevInclude) {
      // Although this reactive block should only be called when `include` has in fact changed, it will also be called once when this component is created.
      // This conditional prevents the overview being re-updating a ton of times each time the segment widgets are loaded
      refreshOverviewCallback();
    }
    prevInclude = segmentInfo.include;
  }
</script>

<div
  class="box"
  style="--own-bg-color: {backgroundColor}; --own-txt-color: {textColor}"
>
  <div class="header-bar">
    <Checkbox
      checked="{segmentInfo.include}"
      bind:value="{segmentInfo.include}"
    />
    {segmentInfo.name} ({segmentInfo.permissions.toUpperCase()})
  </div>
  <div class="details-box">
    {#if segmentInfo.include}
      [0x{segmentInfo.size.toString(16)} bytes] =>
      <label
        class="seg-vaddr-input"
        class:warning="{!validVaddr(segmentInfo.allocatedVaddr)}"
      >
        <input
          class="seg-vaddr-input"
          class:warning="{!validVaddr(segmentInfo.allocatedVaddr)}"
          placeholder="{placeholderVaddr}"
          bind:value="{inputVaddr}"
          on:focusout="{updatePlaceholderVaddr}"
        />
      </label>
    {:else}
      [0x{segmentInfo.size.toString(16)} bytes] (discarded)
    {/if}
  </div>
</div>
