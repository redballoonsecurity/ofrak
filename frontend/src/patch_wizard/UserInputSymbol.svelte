<style>
  .box {
    display: inline-flex;
    align-items: center;
    height: fit-content;
    border: thin solid;
    width: 100%;
  }

  label {
    background-color: var(--main-bg-color);
    color: var(--main-fg-color);
    width: 40%;
    margin: 0.5em;
  }

  input {
    background-color: var(--main-bg-color);
    color: var(--main-fg-color);
    width: 100%;
  }

  .name-label {
    margin-right: auto;
  }

  .vaddr-label {
    margin-left: auto;
    margin-right: auto;
  }
</style>

<script>
  import Button from "../utils/Button.svelte";
  import Icon from "../utils/Icon.svelte";

  export let name,
    vaddr,
    deleteSym = () => {};

  let _vaddr = "0x" + vaddr.toString(16),
    prevVaddr = vaddr;

  $: {
    if (vaddr !== prevVaddr) {
      // vaddr has been bound and changed by outside forces
      _vaddr = "0x" + vaddr.toString(16);
    } else {
      vaddr = _vaddr.startsWith("0x") ? parseInt(_vaddr, 16) : parseInt(_vaddr);
    }
    prevVaddr = vaddr;
  }
</script>

<div class="box">
  <label class="name-label">
    <input placeholder="{name}" bind:value="{name}" />
  </label>

  <label class="vaddr-label">
    <input placeholder="{vaddr}" bind:value="{_vaddr}" />
  </label>

  <Button on:click="{deleteSym}" --button-margin="0.5em 0.5em 0.5em auto"
    ><Icon url="/icons/trash.svg" /></Button
  >
</div>
