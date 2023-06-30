<script>
  import Checkbox from "../Checkbox.svelte";
  export let option, selection, focus;
  function onCheck() {
    focus = option;
    selection = option;
  }
  $: selected = selection === option;
</script>

<div>
  <Checkbox onselect="{onCheck}" bind:checked="{selected}" leftbox="{true}"
    >{option}</Checkbox
  >
</div>
