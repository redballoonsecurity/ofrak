<style>
  .box {
    display: inline-flex;
    align-items: center;
    height: fit-content;
  }

  label {
    background-color: var(--main-bg-color);
    color: var(--main-fg-color);
    max-width: 10em;
  }

  input {
    background-color: var(--main-bg-color);
    color: var(--main-fg-color);
    max-width: 10em;
  }
</style>

<script>
  import Button from "../utils/Button.svelte";

  export let name,
    vaddr,
    deleteSym = () => {},
    saveSym = () => {};

  let _name = name;
  let _vaddr = vaddr;
</script>

<div class="box">
  <label>
    <input placeholder="{name}" bind:value="{name}" />
  </label>

  <label>
    <input placeholder="{vaddr}" bind:value="{vaddr}" />
  </label>

  <Button on:click="{saveSym}">Save</Button>
  <Button on:click="{deleteSym}">Delete</Button>
</div>
