<style>
  button {
    padding-top: 0.5em;
    padding-bottom: 0.5em;
    padding-left: 1em;
    padding-right: 1em;
  }

  button:hover,
  button:focus {
    outline: none;
    box-shadow: inset 1px 1px 0 var(--main-fg-color),
      inset -1px -1px 0 var(--main-fg-color);
  }

  button:active {
    box-shadow: inset 2px 2px 0 var(--main-fg-color),
      inset -2px -2px 0 var(--main-fg-color);
  }

  .container {
    min-height: 100%;
    display: flex;
    flex-direction: column;
    flex-wrap: nowrap;
    justify-content: center;
    align-items: stretch;
    align-content: center;
  }
</style>

<script>
  import BinaryModifyView from "./BinaryModifyView.svelte";
  import FindReplaceView from "./FindReplaceView.svelte";
  import Button from "./utils/Button.svelte"

  export let modifierView;
</script>

<div class="container">
  <Button on:click="{() => (modifierView = FindReplaceView)}">
    Modify String
  </Button>
  <Button on:click="{() => (modifierView = BinaryModifyView)}">
    Modify Binary
  </Button>
  <Button on:click="{() => (modifierView = undefined)}">Cancel</Button>
</div>
