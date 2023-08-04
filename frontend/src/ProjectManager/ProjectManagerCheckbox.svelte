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
  let userChecked;

  $: if (selection !== undefined && userChecked !== undefined) {
    if (selection.includes(option)) {
      if (!userChecked) {
        selection.splice(selection.indexOf(option), 1);
      }
    } else {
      if (userChecked) {
        selection.push(option);
      }
    }
  }
</script>

<div class="checkbox">
  <!-- Selection may be an empty list ("falsey") but we still want a checkbox -->
  {#if selection !== undefined}
    <Checkbox checked="{checked}" bind:value="{userChecked}" leftbox="{true}" />
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
