<script>
  import Checkbox from "./Checkbox.svelte";

  export let selectedValue,
    ownValue,
    leftbox = false,
    nomargin = false;

  let thisSelected;

  $: if (thisSelected) {
    selectedValue = ownValue;
  }
</script>

<Checkbox
  leftbox="{leftbox}"
  nomargin="{nomargin}"
  checked="{selectedValue === ownValue}"
  bind:value="{thisSelected}"
>
  <slot />
</Checkbox>
