<style>
  .box {
    display: inline;
  }

  label {
    background-color: var(--main-bg-color);
    color: var(--main-fg-color);
    max-width: 10em;
  }
</style>

<script>
  import Button from "../utils/Button.svelte";

  export let name, vaddr;

  let _name = name;
  let _vaddr = vaddr;
</script>

<div class="box">
  <label>
    <input placeholder="{_name}" bind:value="{_name}" />
  </label>

  <label>
    <input placeholder="{_vaddr}" bind:value="{_vaddr}" />
  </label>

  <Button>Save</Button>
  <Button>Delete</Button>
</div>
