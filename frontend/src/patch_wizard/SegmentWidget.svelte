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

  export let segmentInfo;

  function validVaddr(vaddr) {
    return vaddr || 0 === vaddr;
  }

  let placeholderVaddr, inputVaddr;

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
  }

  $: {
    if (segmentInfo.include) {
      backgroundColor = segmentInfo.color;
      textColor = $settings.background;
    } else {
      backgroundColor = $settings.background;
      textColor = $settings.foreground;
    }
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
        class="{validVaddr(segmentInfo.allocatedVaddr)
          ? 'seg-vaddr-input'
          : 'seg-vaddr-input warning'}"
      >
        <input
          class="{validVaddr(segmentInfo.allocatedVaddr)
            ? 'seg-vaddr-input'
            : 'seg-vaddr-input warning'}"
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
