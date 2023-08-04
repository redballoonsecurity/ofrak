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
  export let ownValue,
    inclusiveSelectionGroup = undefined,
    exclusiveSelectionValue = undefined,
    focus;
  let inclusiveCheckboxChecked;

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
    <span class="checkwrapper">
      <Checkbox
        checked="{inclusiveSelectionGroup?.includes(ownValue)}"
        bind:value="{inclusiveCheckboxChecked}"
        leftbox="{true}"
      />
    </span>
  {/if}
  {#if exclusiveSelectionValue !== undefined}
    <span class="checkwrapper">
      <ExclusiveCheckbox
        leftbox="{true}"
        bind:selectedValue="{exclusiveSelectionValue}"
        ownValue="{ownValue}"
      />
    </span>
  {/if}
  <button
    class="ownValue"
    on:click="{() => {
      focus = ownValue;
    }}"
  >
    {ownValue}
  </button>
</div>
