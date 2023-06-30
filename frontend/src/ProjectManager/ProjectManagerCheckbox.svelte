<script>
  import Checkbox from "../Checkbox.svelte";
  export let option, selection, focus;
  let selected;
  
  $: focus = selection;
  $: if (selected) {
    selection = option
  }
</script>

<div>
  <Checkbox checked="{selection===option}" bind:value="{selected}" leftbox="{true}"
    >{option}</Checkbox
  >
</div>
