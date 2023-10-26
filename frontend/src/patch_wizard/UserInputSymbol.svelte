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
</script>

<div class="box">
  <label class="name-label">
    <input placeholder="{name}" bind:value="{name}" />
  </label>

  <label class="vaddr-label">
    <input placeholder="{vaddr}" bind:value="{vaddr}" />
  </label>

  <Button on:click="{deleteSym}" --button-margin-left="auto"
    ><Icon url="/icons/trash.svg" /></Button
  >
</div>
