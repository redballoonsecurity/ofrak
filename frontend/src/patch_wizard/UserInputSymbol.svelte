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
  import Icon from "../utils/Icon.svelte";

  export let name,
    vaddr,
    deleteSym = () => {};
</script>

<div class="box">
  <label>
    <input placeholder="{name}" bind:value="{name}" />
  </label>

  <label>
    <input placeholder="{vaddr}" bind:value="{vaddr}" />
  </label>

  <Button on:click="{deleteSym}"><Icon url="/icons/trash.svg" /></Button>
</div>
