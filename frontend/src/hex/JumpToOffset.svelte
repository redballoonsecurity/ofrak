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
  import { onMount } from "svelte";
  import { shortcuts } from "../keyboard";
  export let currentPosition;
  let input,
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
</script>

<input
  type="text"
  on:keyup="{(e) => {
    if (e.key === 'Enter') {
      input.blur();
      try {
        currentPosition =
          Math.floor(calculator.calculate(input.value) / alignment) * alignment;
      } catch (_) {
        input.value = `0x${currentPosition.toString(alignment)}`;
      }
    }
  }}"
  bind:this="{input}"
  value="0x{currentPosition.toString(alignment)}"
/>
