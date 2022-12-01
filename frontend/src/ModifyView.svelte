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

  /*
  .actions {
    margin-top: 2em;
    display: flex;
    flex-direction: row;
    flex-wrap: nowrap;
    justify-content: space-evenly;
    align-items: center;
    align-content: center;
  }
  */
</style>

<script>
  import BinaryModifyView from "./BinaryModifyView.svelte";
  import FindReplaceView from "./FindReplaceView.svelte";

  export let modifierView;
</script>

<div class="container">
  <button on:click="{() => (modifierView = FindReplaceView)}">
    Modify String
  </button>
  <button on:click="{() => (modifierView = BinaryModifyView)}">
    Modify Binary
  </button>
  <button on:click="{() => (modifierView = undefined)}">Cancel</button>
</div>
