<style>
  .checkbox {
    margin-block: 1em;
    margin-left: 1em;
    margin-top: 1em;
  }

  .ownValue {
    margin-right: 1em;
    display: inline-flex;
    flex-direction: row;
    flex-wrap: nowrap;
    justify-content: flex-start;
    align-items: center;
    align-content: stretch;
    white-space: nowrap;
    user-select: none;
    cursor: pointer;
    border-style: none;
  }

  .checkwrapper {
    display: inline-flex;
  }
</style>

<script>
  import Checkbox from "../Checkbox.svelte";
  import ExclusiveCheckbox from "../ExclusiveCheckbox.svelte";
  import Button from "../utils/Button.svelte";

  export let ownValue,
    inclusiveSelectionGroup = undefined,
    exclusiveSelectionValue = undefined,
    focus,
    mouseoverInfo = {},
    inclusiveCheckboxChecked;

  $: if (
    inclusiveSelectionGroup !== undefined &&
    inclusiveCheckboxChecked !== undefined
  ) {
    if (inclusiveSelectionGroup.includes(ownValue)) {
      if (!inclusiveCheckboxChecked) {
        inclusiveSelectionGroup.splice(
          inclusiveSelectionGroup.indexOf(ownValue),
          1
        );
      }
    } else {
      if (inclusiveCheckboxChecked) {
        inclusiveSelectionGroup.push(ownValue);
      }
    }
  }
</script>

<div class="checkbox">
  <!-- May be an empty list ("falsey") but we still want a checkbox -->
  {#if inclusiveSelectionGroup !== undefined}
    <span
      class="checkwrapper"
      on:mouseenter="{() => {
        mouseoverInfo.onInclusive = true;
        mouseoverInfo.inclusiveChecked = inclusiveCheckboxChecked;
      }}"
      on:mouseleave="{() => {
        mouseoverInfo.onInclusive = false;
        mouseoverInfo.inclusiveChecked = undefined;
      }}"
    >
      <Checkbox
        checked="{inclusiveSelectionGroup?.includes(ownValue)}"
        bind:value="{inclusiveCheckboxChecked}"
        leftbox="{true}"
      />
    </span>
  {/if}
  {#if exclusiveSelectionValue !== undefined}
    <span
      class="checkwrapper"
      on:mouseenter="{() => {
        mouseoverInfo.onExclusive = true;
        mouseoverInfo.exclusiveChecked = exclusiveSelectionValue === ownValue;
      }}"
      on:mouseleave="{() => {
        mouseoverInfo.onExclusive = false;
        mouseoverInfo.exclusiveChecked = undefined;
      }}"
    >
      <ExclusiveCheckbox
        leftbox="{true}"
        bind:selectedValue="{exclusiveSelectionValue}"
        ownValue="{ownValue}"
      />
    </span>
  {/if}
  <div class="ownValue">
    <Button
      on:click="{() => {
        focus = ownValue;
      }}"
    >
      {ownValue}
    </Button>
  </div>
</div>
