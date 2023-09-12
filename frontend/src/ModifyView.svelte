<style>
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
  import Button from "./utils/Button.svelte";

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
