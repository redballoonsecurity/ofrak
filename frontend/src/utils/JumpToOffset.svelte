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
  import { calculator } from "../helpers";
  import { onMount, tick } from "svelte";
  import { shortcuts } from "../keyboard";

  export let dataLenPromise, scrollY;
  let startOffset,
    input,
    mounted = false;
  const alignment = 16;

  let dataLength = 0;

  $: dataLenPromise.then((r) => {
    dataLength = r;
  });

  onMount(() => {
    mounted = true;
  });

  $: shortcuts["g"] = () => {
    if (input) {
      input.focus();
    }
  };

  $: if (mounted) {
    startOffset = Math.max(
      Math.floor((dataLength * $scrollY.top) / alignment) * alignment,
      0
    );
    input.value = `0x${startOffset.toString(16)}`;
  }
</script>

<input
  type="text"
  on:keyup="{(e) => {
    if (e.key === 'Enter') {
      input.blur();
      try {
        let result = calculator.calculate(input.value) + 1;
        $scrollY.top = result / dataLength;
      } catch (_) {
        input.value = `0x${startOffset.toString(16)}`;
      }
    }
  }}"
  bind:this="{input}"
/>
