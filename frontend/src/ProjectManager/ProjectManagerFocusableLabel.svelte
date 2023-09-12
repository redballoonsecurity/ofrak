<script>
  import Button from "../utils/Button.svelte";
  export let focus, label, newFocus;
  function focusLabel() {
    focus = newFocus;
  }
</script>

<Button on:click="{focusLabel}">{label}</Button>
