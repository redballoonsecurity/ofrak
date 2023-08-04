<style>
  .checkbox {
    margin-block: 1em;
    margin-left: 1em;
    margin-top: 1em;
  }

  .option {
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
</style>

<script>
  import Checkbox from "../Checkbox.svelte";
  export let option,
    selection = undefined,
    focus;
  let checked = selection?.includes(option);

  $: if (selection !== undefined) {
    if (checked && !selection.includes(option)) {
      selection.push(option);
    } else {
      const idx = selection.indexOf(option);
      if (idx >= 0) {
        selection.splice(idx, 1);
      }
    }
  }
</script>

<div class="checkbox">
  <!-- Selection may be an empty list ("falsey") but we still want a checkbox -->
  {#if selection !== undefined}
    <Checkbox bind:checked="{checked}" leftbox="{true}" />
  {/if}
  <button
    class="option"
    on:click="{() => {
      focus = option;
    }}"
  >
    {option}
  </button>
</div>
