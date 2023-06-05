<style>
  input {
    margin-bottom: 1em;
    width: 125%;
    background: inherit;
    color: inherit;
    border: none;
    text-align: center;
  }

  input:focus {
    outline: none;
    box-shadow: inset 0 -1px 0 var(--main-fg-color);
  }
</style>

<script>
  import { calculator } from "./helpers";
  import { onMount, tick } from "svelte";
  import { shortcuts } from "./keyboard";
  import { selectedResource } from "./stores.js";

  export let scrollY;
  let startOffset,
    input,
    mounted = false;
  const alignment = 16;

  onMount(() => {
    mounted = true;
  });

  $: shortcuts["g"] = () => {
    if (input) {
      input.focus();
    }
  };

  async function getStartOffset() {
    let dataLength = await $selectedResource.get_data_length();
    startOffset = Math.max(
      Math.floor((dataLength * $scrollY.top) / alignment) * alignment,
      0
    );
    input.value = `0x${startOffset.toString(16)}`;
  }

  $: if (mounted) {
    getStartOffset();
  }
</script>

<input
  type="text"
  on:keyup="{async (e) => {
    if (e.key === 'Enter') {
      input.blur();
      try {
        let dataLength = await $selectedResource.get_data_length();
        let result = calculator.calculate(input.value) + 1;
        $scrollY.top = result / dataLength;
      } catch (_) {
        input.value = `0x${startOffset.toString(16)}`;
      }
    }
  }}"
  bind:this="{input}"
/>
