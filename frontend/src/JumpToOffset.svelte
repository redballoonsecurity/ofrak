<style>
  input {
    margin-bottom: 1em;
    max-width: 100%;
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

  export let dataPromise, scrollY;
  let startOffset,
    input,
    mounted = false;
  const alignment = 16;

  let dataLength = 0;
  dataPromise.then((data) => {
    dataLength = data.byteLength;
  });

  onMount(() => {
    mounted = true;
  });

  $: if (mounted) {
    startOffset = Math.max(
      Math.ceil((dataLength * $scrollY.top) / alignment) * alignment,
      0
    );
    input.value = `0x${startOffset.toString(16)}`;
  }
</script>

<input
  type="text"
  on:focusout="{() => {
    try {
      let result = calculator.calculate(input.value);
      $scrollY.top = result / dataLength;
    } catch (_) {
      input.value = `0x${startOffset.toString(16)}`;
    }
  }}"
  on:keyup="{(e) => {
    if (e.key === 'Enter') {
      input.blur();
    }
  }}"
  on:input="{async () => {
    let { value, selectionStart, selectionEnd } = input;
    input.value = value.replace(/\n/g, '');
    await tick();
    input.selectionStart = selectionStart;
    input.selectionEnd = selectionEnd;
  }}"
  bind:this="{input}"
/>
