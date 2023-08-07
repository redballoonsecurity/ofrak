<style>
  .hbox {
    width: 100%;
    height: 100%;
  }
  .options {
    display: flex;
    flex-direction: column;
    margin: 1em;
    font-size: x-large;
  }
</style>

<script>
  export let focus;
</script>

<div class="hbox">
  <div class="options">
    {#if focus && typeof focus == "string"}
      "{focus}"
    {:else if focus && typeof focus == "object"}
      <svelte:component this="{focus['object']}" {...focus["args"]} />
    {:else}
      Click anywhere to see its options.
    {/if}
  </div>
</div>
