<style>
  button {
    border: none;
    padding: 2px;
    font-size: xx-large;
    font-weight: bold;
    text-transform: uppercase;
  }
</style>

<script>
  import Button from "../utils/Button.svelte";
  export let focus, label, newFocus;
  function focusLabel() {
    focus = newFocus;
  }
</script>

<button on:click="{focusLabel}">{label}</button>
