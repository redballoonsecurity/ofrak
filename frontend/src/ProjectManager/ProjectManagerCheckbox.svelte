<style>
  .checkbox {
    margin-block: 1em;
    margin-left: 1em;
    margin-top: 1em;
  }
</style>

<script>
  import Checkbox from "../Checkbox.svelte";
  export let option, selection, focus;
  let selected;

  $: focus = selection;
  $: if (selected) {
    selection = option;
  }
</script>

<div class="checkbox">
  <Checkbox
    checked="{selection === option}"
    bind:value="{selected}"
    leftbox="{true}">{option}</Checkbox
  >
</div>
